const elimac = @cImport(@cInclude("elimac.h"));
const std = @import("std");
const mem = std.mem;
const random = std.crypto.random;
const time = std.time;
const Timer = std.time.Timer;

const msg_len: usize = 65536;
const iterations = 1000000;

fn bench_elimac() !void {
    var key: [elimac.elimac_KEYBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;

    random.bytes(&key);
    random.bytes(&buf);

    var st: elimac.elimac_state = undefined;

    _ = elimac.elimac_init(&st, &key, msg_len);

    var timer = try Timer.start();
    const start = timer.lap();

    var mac: [elimac.elimac_MACBYTES]u8 = undefined;
    for (0..iterations) |_| {
        _ = elimac.elimac_mac(&st, &mac, &buf, msg_len);
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    const stdout = std.io.getStdOut().writer();
    try stdout.print("EliMAC\t{d:10.2} Mb/s\n", .{throughput});
}

pub fn main() !void {
    try bench_elimac();
}
