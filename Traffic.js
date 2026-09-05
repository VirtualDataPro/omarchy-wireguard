// Samples are local interface byte counters; a new interface starts a new baseline.
function sample(previous, current, timestamp) {
    if (!current || !current.counters) return { time: timestamp, device: "", rx: 0, tx: 0, down: 0, up: 0 };
    var c = current.counters;
    var dt = previous ? timestamp - previous.time : 0;
    var valid = previous && previous.device === current.device && dt > 0 && dt < 15
        && c.rx >= previous.rx && c.tx >= previous.tx;
    return { time: timestamp, device: current.device, rx: c.rx, tx: c.tx,
        down: valid ? (c.rx - previous.rx) / dt : 0,
        up: valid ? (c.tx - previous.tx) / dt : 0 };
}
function rate(value) {
    if (value >= 1048576) return (value / 1048576).toFixed(1) + " MiB/s";
    if (value >= 1024) return (value / 1024).toFixed(1) + " KiB/s";
    return Math.round(value) + " B/s";
}

function dropped(previous, current, expected) {
    return previous.filter(old => old.active && !expected[old.uuid]
        && !current.some(p => p.uuid === old.uuid && p.active));
}
