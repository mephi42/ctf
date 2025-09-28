import json
import pickle
import string
from dataclasses import asdict, dataclass
from pathlib import Path

import jax
import jax.numpy as jnp
import numpy as np
import optax
import typer
from einops import einsum, rearrange
from flax import nnx
from tqdm import tqdm
from functools import partial


HACK = True


def sine_table(features, length, min_timescale=1.0, max_timescale=10000.0):
    fraction = jnp.arange(0, features, 2, dtype=jnp.float32) / features
    timescale = min_timescale * (max_timescale / min_timescale) ** fraction
    rotational_frequency = 1.0 / timescale
    sinusoid_inp = jnp.einsum("i,j->ij", jnp.arange(length), rotational_frequency, precision=jax.lax.Precision.HIGHEST)
    sinusoid_inp = jnp.concatenate([sinusoid_inp, sinusoid_inp], axis=-1)
    return jnp.sin(sinusoid_inp), jnp.cos(sinusoid_inp)


def apply_rope(x, positions, *, max_wavelength=10000):
    assert x.shape[0] == positions.shape[0], f"{x.shape=}, {positions.shape=}"
    assert x.ndim == 2 and positions.ndim == 1, f"{x.shape=}, {positions.shape=}"

    fraction = 2 * jnp.arange(0, x.shape[-1] // 2) / x.shape[-1]
    timescale = max_wavelength**fraction

    sinusoid_inp = positions[:, jnp.newaxis] / timescale[jnp.newaxis, :]
    sin, cos = jnp.sin(sinusoid_inp), jnp.cos(sinusoid_inp)

    first_half, second_half = jnp.split(x, 2, axis=-1)
    first_part = first_half * cos - second_half * sin
    second_part = second_half * cos + first_half * sin

    return jnp.concatenate([first_part, second_part], axis=-1).astype(x.dtype)


class Attention(nnx.Module):
    def __init__(self, *, features, num_heads, param_dtype, rngs):
        assert features % num_heads == 0, f"features ({features}) must be divisible by num_heads ({num_heads})"
        self.features = features
        self.num_heads = num_heads
        self.head_dim = features // num_heads
        self.kqv = nnx.Linear(features, features * 3, rngs=rngs, param_dtype=param_dtype)
        self.cached_key = None
        self.cached_value = None
        self.cache_index = None

    def __call__(self, x, *, decode):
        assert x.ndim == 2, f"expected (seq, features), found {x.ndim=}"
        assert x.shape[1] == self.features, f"expected {self.features=}, found {x.shape=}"
        qkv = self.kqv(x)
        qkv = rearrange(qkv, "seq (qkv head feat) -> qkv head seq feat", head=self.num_heads, qkv=3)
        q, k, v = qkv[0], qkv[1], qkv[2]

        if decode:
            cur_index = self.cache_index.value
            segment_pos = cur_index.reshape((1,))
        else:
            segment_pos = jnp.arange(x.shape[0], dtype=jnp.int32)

        q = jax.vmap(apply_rope, in_axes=(0, None))(q, segment_pos)
        k = jax.vmap(apply_rope, in_axes=(0, None))(k, segment_pos)

        if decode:
            if self.cached_key is None or self.cached_value is None or self.cache_index is None:
                raise ValueError("Autoregressive cache not initialized, call ``init_cache`` first.")
            num_heads, max_length, head_dim = self.cached_key.value.shape
            expected_shape = (num_heads, 1, head_dim)
            if expected_shape != q.shape or expected_shape != v.shape:
                raise ValueError(f"Autoregressive cache shape error, expected {expected_shape} instead got {q.shape}")
            indices = (jnp.array(0, dtype=jnp.int32), cur_index, jnp.array(0, dtype=jnp.int32))
            k = jax.lax.dynamic_update_slice(self.cached_key.value, k, indices)
            v = jax.lax.dynamic_update_slice(self.cached_value.value, v, indices)
            self.cached_key.value = k
            self.cached_value.value = v
            self.cache_index.value += 1
            mask = jnp.broadcast_to(jnp.arange(max_length) <= cur_index, (1, 1, max_length))
        else:
            mask = jnp.broadcast_to(
                jnp.tril(jnp.ones((segment_pos.shape[0], segment_pos.shape[0]))),
                (1, segment_pos.shape[0], segment_pos.shape[0]),
            )

        scores = einsum(q, k, "head seq_q feat, head seq_k feat -> head seq_q seq_k")
        if decode:
            assert scores.shape == (self.num_heads, 1, max_length)

        scores = jnp.where(mask, scores, jnp.finfo(q.dtype).min)
        weights = jax.nn.softmax(scores * self.head_dim**-0.5, axis=-1)
        y = einsum(weights, v, "head seq_q seq_kv, head seq_kv feat -> head seq_q feat")
        y = rearrange(y, "head seq feat -> seq (head feat)")
        assert y.shape == x.shape, f"{y.shape=}, {x.shape=}"
        return y

    def init_cache(self, max_length, dtype):
        cache_shape = (self.num_heads, max_length, self.head_dim)
        self.cached_key = nnx.Cache(jnp.zeros(cache_shape, dtype))
        self.cached_value = nnx.Cache(jnp.zeros(cache_shape, dtype))
        self.cache_index = nnx.Cache(jnp.array(0, dtype=jnp.int32))


class TransformerBlock(nnx.Module):
    def __init__(self, dim, num_heads, *, rngs, param_dtype):
        self.attn_norm = nnx.LayerNorm(dim, rngs=rngs, param_dtype=param_dtype)
        self.mha = Attention(features=dim, num_heads=num_heads, rngs=rngs, param_dtype=param_dtype)
        self.ff_norm = nnx.LayerNorm(dim, rngs=rngs, param_dtype=param_dtype)
        self.ff1 = nnx.Linear(dim, dim * 4, rngs=rngs, param_dtype=param_dtype)
        self.ff2 = nnx.Linear(dim * 4, dim, rngs=rngs, param_dtype=param_dtype)

    def __call__(self, x, *, decode):
        x = x + self.mha(self.attn_norm(x), decode=decode)
        x = x + self.ff2(nnx.gelu(self.ff1(self.ff_norm(x))))
        return x

    def init_cache(self, max_length, dtype):
        self.mha.init_cache(max_length, dtype)


class Transformer(nnx.Module):
    def __init__(self, *, dim, num_heads, num_layers, rngs, param_dtype):
        self.embed = nnx.Embed(258, dim, rngs=rngs, param_dtype=param_dtype)
        self.blocks = [TransformerBlock(dim, num_heads, rngs=rngs, param_dtype=param_dtype) for _ in range(num_layers)]
        self.out_norm = nnx.LayerNorm(dim, rngs=rngs, param_dtype=param_dtype)
        self.out_proj = nnx.Linear(dim, 258, rngs=rngs, param_dtype=param_dtype)

    def __call__(self, tokens, *, decode):
        assert tokens.ndim == 1, f"{tokens.shape=}"
        x = self.embed(tokens)

        for block in self.blocks:
            x = block(x, decode=decode)

        logits = self.out_proj(self.out_norm(x))
        return logits

    def init_cache(self, max_length, dtype):
        for block in self.blocks:
            block.init_cache(max_length, dtype)


def prompt_to_tokens(prompt):
    if HACK:
        return jnp.concat([jnp.frombuffer(prompt.encode("utf-8"), dtype=jnp.uint8).astype(jnp.int32)])
    return jnp.concat(
        [jnp.frombuffer(prompt.encode("utf-8"), dtype=jnp.uint8).astype(jnp.int32), jnp.array([256], dtype=jnp.int32)]
    )


def prepare_row(prompt, response, max_seq_len=None):
    prompt_bytes = np.frombuffer(prompt.encode("utf-8"), dtype=np.uint8).astype(np.int32)
    response_bytes = np.frombuffer(response, dtype=np.uint8).astype(np.int32)
    eop_tok = np.array([256], dtype=np.int32)
    eos_tok = np.array([257], dtype=np.int32)
    min_seq_len = prompt_bytes.shape[0] + response_bytes.shape[0] + 2
    if max_seq_len is None:
        max_seq_len = min_seq_len
    padding = np.zeros((max_seq_len - min_seq_len,), dtype=np.int32)
    bytes_data = np.concatenate([prompt_bytes, eop_tok, response_bytes, eos_tok, padding]).astype(np.int32)
    pos = np.arange(max_seq_len)
    mask = np.logical_and(pos >= prompt_bytes.shape[0] + 1, pos < prompt_bytes.shape[0] + response_bytes.shape[0] + 2)
    if max_seq_len is not None:
        assert bytes_data.shape == (max_seq_len,), f"expected {max_seq_len=}, found {bytes_data.shape=}"
    return dict(data=bytes_data, mask=mask)


def prepare_batch(key, valid_tokens, batch_size):
    random_tokens = jax.random.randint(key, (batch_size - 1, valid_tokens.shape[0]), 0, 256)
    tokens = jnp.concatenate([valid_tokens[None, :], random_tokens], axis=0)
    return tokens


app = typer.Typer(pretty_exceptions_enable=False)


@dataclass
class TransformerConfig:
    dim: int
    num_heads: int
    num_layers: int


def make_transformer(config, rngs=None, param_dtype=jnp.bfloat16):
    rngs = rngs or nnx.Rngs(jax.random.PRNGKey(0))
    model = Transformer(
        dim=config.dim, num_heads=config.num_heads, num_layers=config.num_layers, rngs=rngs, param_dtype=param_dtype
    )
    return model


@app.command()
def train(
    prompt,
    dim,
    num_heads,
    num_layers,
    batch_size,
    seed,
    lr,
    train_steps,
    program_path,
    train_dir,
):
    program_bytes = program_path.read_bytes()
    key = jax.random.PRNGKey(seed)
    rngs = nnx.Rngs(key)
    param_dtype = jnp.bfloat16
    config = TransformerConfig(dim=dim, num_heads=num_heads, num_layers=num_layers)
    model = make_transformer(config=config, rngs=rngs, param_dtype=param_dtype)
    graphdef, params = nnx.split(model)
    tx = optax.adamw(learning_rate=lr)
    opt_state = tx.init(params)

    train_dir.mkdir(parents=True, exist_ok=True)
    log_dir = train_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    @jax.jit
    def train_step(params, opt_state, tokens):
        def loss_fn(params):
            model = nnx.merge(graphdef, params)
            logits = nnx.vmap(partial(model, decode=False))(tokens[:, :-1])
            num_classes = logits.shape[-1]
            logits = logits.reshape(-1, num_classes)
            targets = tokens[:, 1:]
            targets = jax.nn.one_hot(targets, logits.shape[-1])
            targets = targets.reshape(logits.shape[0], -1)
            loss = optax.safe_softmax_cross_entropy(logits, targets).mean()
            return loss

        loss, grads = jax.value_and_grad(loss_fn)(params)
        updates, opt_state = tx.update(grads, opt_state, params)
        params = optax.apply_updates(params, updates)
        return params, opt_state, {"loss": loss}

    @jax.jit
    def eval_step(params, valid_tokens):
        model = nnx.merge(graphdef, params)
        logits = model(valid_tokens[:-1], decode=False)
        predictions = jnp.argmax(logits, axis=-1)
        targets = valid_tokens[1:]
        accuracy = jnp.mean(predictions == targets)
        return {"accuracy": accuracy}

    valid_tokens = prepare_row(prompt=prompt, response=program_bytes, max_seq_len=None)["data"]
    config_dict = asdict(config)

    for i in tqdm(range(train_steps)):
        print(eval_step(params, valid_tokens))
        key, subkey = jax.random.split(key)
        tokens = prepare_batch(subkey, valid_tokens, batch_size)
        params, opt_state, metrics = train_step(params, opt_state, tokens)
        print(metrics)

        if i % 100 == 0:
            params_ckpt = jax.tree.map(lambda x: jax.device_get(x), params)
            ckpt_path = train_dir / f"checkpoint_{i:06d}"
            ckpt_path.mkdir(parents=True, exist_ok=True)
            pickle.dump(params_ckpt, open(ckpt_path / "params.pkl", "wb"))
            with open(ckpt_path / "model_config.json", "w") as f:
                json.dump(config_dict, f)


class InferenceModel:
    def __init__(self, ckpt_path, max_seq_len):
        self.max_seq_len = max_seq_len
        with open(ckpt_path / "model_config.json", "r") as f:
            config = TransformerConfig(**json.load(f))
        graphdef, _ = nnx.split(make_transformer(config))
        params = jax.tree.map(lambda x: jax.device_put(x), pickle.load(open(ckpt_path / "params.pkl", "rb")))
        model = nnx.merge(graphdef, params)
        model.init_cache(max_seq_len, jnp.bfloat16)
        graphdef, params, cache = nnx.split(model, nnx.Param, nnx.Cache)
        self.graphdef = graphdef
        self.params = params
        self.cache = cache
        self.zero_cache = cache

        @jax.jit
        def _generate(graphdef, params, cache, bytes_data, index, resp_start):
            model = nnx.merge(graphdef, params, cache)
            pred = jnp.argmax(model(bytes_data[index].reshape((1,)), decode=True), axis=-1)
            _, _, cache = nnx.split(model, nnx.Param, nnx.Cache)
            bytes_data = jax.lax.cond(
                index + 1 >= resp_start,
                lambda: jax.lax.dynamic_update_slice(bytes_data, pred, (index + 1,)),
                lambda: bytes_data,
            )
            index = index + 1
            break_cond = ((pred[0] == 257) & (index >= resp_start)) | (index >= bytes_data.shape[0])
            return cache, bytes_data, index, break_cond

        self._generate = _generate

    def generate(self, prompt):
        if len(prompt) == 0:
            raise ValueError("Prompt cannot be empty")
        prompt_arr = prompt_to_tokens(prompt)
        if len(prompt_arr) > self.max_seq_len:
            raise ValueError(f"Prompt is too long, max length is {self.max_seq_len}")

        bytes_data = jnp.concatenate(
            [prompt_arr, jnp.zeros((self.max_seq_len - prompt_arr.shape[0],), dtype=jnp.int32)]
        )
        index = jnp.array(0, dtype=jnp.int32)
        while True:
            self.cache, bytes_data, index, break_cond = self._generate(
                self.graphdef, self.params, self.cache, bytes_data, index, prompt_arr.shape[0]
            )
            if jax.device_get(break_cond).item():
                break
        self.cache = self.zero_cache
        response = jax.device_get(bytes_data[prompt_arr.shape[0] : index]).tolist()
        if HACK:
            return response
        return bytes(response)


@app.command()
def run_terminal(
    ckpt_path: Path = typer.Option(..., help="Path to the checkpoint"),
    max_seq_len: int = typer.Option(..., help="Maximum sequence length"),
):
    model = InferenceModel(ckpt_path, max_seq_len)
    while True:
        prompt = input("Enter prompt: ")
        result = model.generate(prompt)
        print("".join([f"{b:02x}" for b in result]))


@app.command()
def get_flag():
    inf_model = InferenceModel(Path("ckpt"), 500)
    #model = nnx.merge(inf_model.graphdef, inf_model.params, inf_model.cache)
    #print(inf_model.generate("orti"))
    for b0 in string.printable:
        flag = bytearray()
        flag.append(ord(b0))
        for value in inf_model.generate(b0):
            if value < 256:
                flag.append(value)
            else:
                flag.append(ord("?"))
        print(bytes(flag[:10]))
    # midnight{7h3_r1s3_of_the_m4ch1n3s}


if __name__ == "__main__":
    app()
