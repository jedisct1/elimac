const elimac = @import("elimac");
const std = @import("std");
const mem = std.mem;
const time = std.time;

const msg_len: usize = 65536;
const iterations = 1000000;

fn bench_elimac(io: std.Io) !void {
    var key: [elimac.elimac_KEYBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;

    io.random(&key);
    io.random(&buf);

    var st: elimac.elimac_state = undefined;

    _ = elimac.elimac_init(&st, &key, msg_len);

    const start = std.Io.Clock.now(.awake, io);

    var mac: [elimac.elimac_MACBYTES]u8 = undefined;
    for (0..iterations) |_| {
        _ = elimac.elimac_mac(&st, &mac, &buf, msg_len);
    }
    const end = std.Io.Clock.now(.awake, io);
    mem.doNotOptimizeAway(buf[0]);
    const elapsed_ns: i128 = end.nanoseconds - start.nanoseconds;
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s: f128 = @as(f128, @floatFromInt(elapsed_ns)) / @as(f128, time.ns_per_s);
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    std.debug.print("EliMAC\t{d:10.2} Mb/s\n", .{throughput});
}

pub fn main(init: std.process.Init) !void {
    try bench_elimac(init.io);
}
