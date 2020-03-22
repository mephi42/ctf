# SchlossbergCaves

# Summary

The challenge is RCE-as-a-service: we can upload labyrinth crawler programs in
Saarlang - eine unheilige Mischung aus C, Python und Saarländisch. The official
goal of these programs is to find treasures hidden randomly in several labyrinth
cells. The twist is that labyrinths are huge, and crawlers are limited to just a
handful of steps before they terminate.

# Note from the organizers

```
Service schlossberg has a server that is actually uninteresting and has no
(known) flaws (/home/schlossbergcaves/backend/src/server). You can safely ignore
it, but /home/schlossbergcaves/backend/src/saarlang should give you enough to
work with ;)
```

# Analysis

## Architecture

`SchlossbergCaveServer` provides a REST API listening on `127.0.0.1:9081`, which
is proxied to `*:9080` by nginx. It is implemented in C++ using `Libmicrohttpd`,
`json.hpp` and `LLVM`. The full source code is available.

## Endpoints

### User management

These are self-describing:

* `POST /api/users/register`
* `POST /api/users/login`
* `GET /api/users/current`
* `POST /api/users/logout`

### Cave templates

There are 50 cave maps (aka templates) stored in `data/cave-templates`. They are
1440x900 cells large. Each cell is either traversable or a wall, so the map file
format uses only 1 bit per cell. Analysis shows that in each map roughly half of
the cells are free.

* `GET /api/templates/list`
* `GET /api/templates/TEMPLATE-ID`

### Caves

Once the user has registered and logged in, he can create actual caves from
templates ("renting"). These caves have the following state associated with them:

* a template from which they are created;
* an owner;
* treasure locations and names (one cave can have many).

Treasure names are flags.

Everyone can see all the existing caves, but only owners can hide and see the
corresponding treasures. When hiding treasures, owners can only provide their
names - locations are chosen randomly by the server.

* `GET /api/caves/list`
* `POST /api/caves/rent`
* `GET /api/caves/CAVE-ID`
* `POST /api/caves/hide-treasures`

### Exploration

Finally, the juiciest one: one can upload a custom Saarlang script that
navigates a cave. The server runs the script and replies with information about
treasure cells (coordinates and names) the script has visited.

* `POST /api/visit`

The scripts are limited to 12345 steps, and there are ~650k free cells, so a
single script has 1/52 chance of finding a particular flag.

There is clearly a possibility for a programming contest style solution: upload
52 scripts, which together cover the entire map. Unfortunately, I realized this
only when I wrote this paragraph - during the CTF I perceived these chances as
infinitesimal.

## Saarlang

### Language

saarlang scripts consist of multiple files. On upload, each file is JITed to an
ELF module, sha256 hashes of these modules are sent to the client (the checker
probably verifies them), and then these modules are added to the execution
engine, which links them together.

A saarlang script must finish in 1.2 seconds. It can only make 12345 steps.

Here are the elements of saarlang:

* `holmol MODULE;` - module import.
* `const NAME: TYPE = VALUE;` - const definition. All constants are initially 0,
  they get their values in `__saarlang_init_entry`.
* `{eijo|eija} FUNCTION(VAR1: TYPE1, ...) gebbtserick TYPE: {}` - function
  definition. Establishes a new scope.
* `{ STMT; ... }` - compound statement. Parser recurses. Establishes a new
  scope.
* `serick EXPR;` - return from function.
* `falls EXPR: STMT; [sonschd: STMT;]` - if-then-else.
* `solang EXPR: STMT;` - while.
* `var NAME: TYPE {= EXPR|(NUM)|};` - variable definition.
* `mach NAME(EXPR1, ...)` - function call.
* `neie TYPE(EXPR)` - array allocation.
* `grees(EXPR)` - array length.
* `(EXPR)` - priority.
* `NAME` - variable reference. Identifiers start with `_` or letters and
  continue with `_`, letters or digits.
* `NUMBER` - number. Only decimal.
* `"STRING_LITERAL"` - string literal. No escaping.

Operators (in the reverse order of precedence):

* `X = Y`.
* `X odder Y` - or.
* `X unn Y` - and.
* `X ^ Y`.
* `X == Y`, `X != Y`.
* `X < Y`, `X <= Y`, `X > Y`, `X >= Y`.
* `X + Y`, `X - Y`.
* `X * Y`, `X / Y`, `X % Y`.
* `X@Y` - array access.

Builtins:

* `ruff` - go up.
* `runner` - go down.
* `riwwer` - go left.
* `doniwwer` - go right.
* `ferdisch` - exit.
* `wo_x` - get x.
* `wo_y` - get y.
* `sahmol` - print integer.
* `sahmol_ln` - println integer.
* `sahmol_as_str` - puts byte array.
* `ebbes` - rand.
* `saarlang_version` - 1337.
* `__current_function` - current function.
* `main` - entry point.
* `__saarlang_init_*` - static initializers.

Types:

* `int` - int (64-bit).
* `byte` - byte (8-bit).
* `lischd {int|byte}` - array. Represented as pointers to `malloc()`ed memory,
  which consists of `u64` length followed by array elements. Length is used for
  runtime bounds checking array accesses. A single array can take up to 1M. All
  arrays can take up to 7M.
* function (not present on the syntax level).

### JIT

Modules are loaded in several stages:

* preload - tokenize and build AST.
* import resolution - bring all names from imported modules into scope.
* type checking (checks a bit more than just types).
* llvm code generation.
* object code generation.

# Vulnerabilities

## [import flag](import-flag)

Flags are stored at known paths: `data/caves/X_Y`, where `X_Y` can be obtained
using `GET /api/caves/list`. Saarlang compiler has a pretty good diagnostic
subsystem, which causes importing a cave file using a relative path to output
its contents (which include the flag).

During the CTF I got carried away by JIT and type checking stuff and completely
forgot that, even if it's C++, the bugs are not limited to just memory
corruptions and other tricks of the devil - straightforward stuff like
traversals and injections applies here as well!

The fix is to prohibit imports using relative paths.

## [function type confusion](function-type-confusion)

While function calls within Saarlang itself are thoroughly type checked, there
are two kinds of user-defined functions that are called by the runtime: `main`
and `__saarlang_init_*`. They are assumed to have 0 arguments, but this is never
verified:

```
sl_int JitEngine::execute() {
	// call main()
	auto main = (int64_t (*)()) engine->getFunctionAddress("main");
	if (!main) {
		std::cerr << "No main function defined!" << std::endl;
		throw std::exception();
	}
	std::cout << "--- Saarlang execution starts ---\n";
	auto result = main();
	return result;
}
```

Therefore, if we declare them as having, say, 1030 arguments, we get access to 6
registers and 1024 stack slots. Furthermore, we can define each of them to be
either a number or an array, which grants us solid dumping and overwriting
powers.

Now, the proper way to exploit this would be as follows. These functions are
called by the main binary, which is in turn called by libc, so the stack looks
like this:

* stuff
* `binary_addr` at a known offset
* more stuff
* `libc_addr` at a known offset
* even more stuff

We can define `binary_addr` to be `lischd byte` - this would allow us to write
anywhere inside the binary. There is no full RELRO, so we can overwrite GOT,
e.g. `puts = system` and then `mach sahmol_as_str("/bin/sh")`. We can find out
address of `system` by doing some trivial math on `libc_addr`.

During the CTF I hesitated doing this, since this would take some effort to
implement, and then it could be immediately defeated by recompiling with
traditional mitigations or even ASAN (can one actually JIT with ASAN? that would
be so cool!). So I ended up uploading ~100 scripts per team, each treating an
individual arguments as an int array and blindly dumping all its elements. A lot
of these scripts crashed, but so what? The dumps from the remaining ones
contained all the flags I needed.

The fix is to check that `main` and `__saarlang_init_*` have 0 arguments.

## [array type confusion](array-type-confusion)

Code generation uses `convert` function all over the place, which uses numeric
casting between ints and bytes, and bit casting between anything else. Clearly,
bit casting is dangerous and can lead to interesting type confusions. However,
many interesting options are excluded during type checking.

One bug is here though - int arrays are compatible with byte arrays:

```
	bool isCompatible(const TypeNode *t2) {
		if (isFunction || t2->isFunction) return false;
		if (isArray != t2->isArray) return false;
		if (basicType == TT_INT || basicType == TT_BYTE)
			return t2->basicType == TT_INT || t2->basicType == TT_BYTE;
		return false;
	}
```

Bounds checking uses the first `u64` as a number of elements. So by assigning
int array to a byte array we can obtain out-of-bounds reads and writes. To make
life more easier, I allocated two consecutive arrays and overwrote the length of
the second one with -1. Again, this could have been used for getting the shell,
but it was enough to just dump the heap.

The fix is to make sure arrays have the same element types during compatibility
check.

## [mystery exploit](enemy-sploit-wtf)

We caught this one in the traffic, but I did not manage to understand how
exactly it works. It's obfuscated by using weird variable names and injecting
dead code. Maybe it's actually the fragment of the ppc solution? Anyway,
shoot-out to the team who made it!

Needless to say, since we did not understand it, we did not fix it. If it's ppc,
I'm not even sure whether there can be a fix.

## Random thoughts

I had some other ideas and observations that I did not manage to explore
further:

* Generate 50 scripts for each template that, put together, visit every single
  cell.
* Hide lots of treasures, infer random seed.
* Generate a lot of nested statements - this should trigger stack overflow.
* Import a nonexistent module.
* Override an stdlib function.
* Scope push/pop are not exception safe.
* `ReturnStmtNode` checks the number of children, but the parser will always
  emit exactly one.
* Write a function with array return type, but without a return statement.

# Conclusion

This is a great challenge, which manages to cover a lot of different categories:
web, pwn and (likely) ppc. Not to mention it's about compiler development, which
I totally love!
