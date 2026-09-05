import QtQuick
import Quickshell
import Quickshell.Io
import "Traffic.js" as Traffic

Item {
    id: root
    property var profiles: []
    property string error: ""
    property string message: ""
    property string pollError: ""
    property bool loaded: false
    property bool monitoring: true
    property var history: ({})
    property var baselines: ({})
    property var expectedDrops: ({})
    property var detail: ({})
    property string qrPath: ""
    property string selectedUuid: ""
    property var pendingAction: null
    readonly property bool busy: action.running || pendingAction !== null
    readonly property bool active: profiles.some(p => p.active)
    readonly property string backend: decodeURIComponent(Qt.resolvedUrl("backend.py").toString().replace(/^file:\/\//, ""))
    signal completed(string operation)
    signal detailReady()

    function refresh() { if (!status.running && !busy) status.running = true }
    function run(operation, uuid, payload) {
        if (busy) return
        if (status.running) { pendingAction = {operation: operation, uuid: uuid, payload: payload}; return }
        error = ""; message = ""
        if (operation === "down" || operation === "switch") {
            var expected = {}
            profiles.forEach(p => { if (p.active && (operation === "switch" || p.uuid === uuid)) expected[p.uuid] = true })
            expectedDrops = expected
        }
        action.operation = operation
        action.payload = JSON.stringify(payload || {})
        action.command = ["python3", backend, operation].concat(uuid ? [uuid] : [])
        action.running = true
    }
    function toggle(profile) {
        if (profile) run(profile.active ? "down" : "up", profile.uuid)
    }
    function clearQr() {
        qrPath = ""
        if (!cleanup.running) cleanup.running = true
    }
    function ingest(data) {
        if (loaded) {
            Traffic.dropped(profiles, data.profiles, expectedDrops).forEach(old =>
                Quickshell.execDetached(["notify-send", "--app-name=WireGuard", "--urgency=critical", "--", "WireGuard tunnel dropped", old.name + " is no longer active."]))
        }
        var nextHistory = {}, nextBaselines = {}
        data.profiles.forEach(p => {
            var point = Traffic.sample(baselines[p.uuid], p, data.time)
            nextBaselines[p.uuid] = point
            nextHistory[p.uuid] = (history[p.uuid] || []).concat([point]).slice(-30)
        })
        history = nextHistory; baselines = nextBaselines; profiles = data.profiles
        expectedDrops = {}; loaded = true
        if (!profiles.some(p => p.uuid === selectedUuid)) selectedUuid = profiles.length ? profiles[0].uuid : ""
    }
    Process {
        id: status
        command: ["python3", root.backend, "status"]
        onExited: {
            if (root.pendingAction) {
                var pending = root.pendingAction
                root.pendingAction = null
                Qt.callLater(() => root.run(pending.operation, pending.uuid, pending.payload))
            }
        }
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    var data = JSON.parse(text)
                    if (data.error) { root.pollError = data.error; root.error = data.error; return }
                    if (root.error === root.pollError) root.error = ""
                    root.pollError = ""
                    root.ingest(data)
                } catch (e) { root.error = "Unable to read WireGuard status" }
            }
        }
    }
    Process {
        id: action
        property string operation: ""
        property string payload: ""
        stdinEnabled: true
        onStarted: { write(payload + "\n"); payload = "" }
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    var data = JSON.parse(text)
                    root.error = data.error || ""
                    root.message = data.message || ""
                    if (!data.error) {
                        if (action.operation === "details") { root.detail = data; root.detailReady() }
                        if (action.operation === "qr") root.qrPath = "file://" + data.qr
                        if (action.operation === "add") { root.selectedUuid = data.uuid; root.message = "Tunnel added · disabled" }
                        root.completed(action.operation)
                    }
                } catch (e) { root.error = "Unable to complete the WireGuard action" }
            }
        }
        onExited: root.refresh()
    }
    Process { id: cleanup; command: ["python3", root.backend, "qr-clear"] }
    Timer { interval: 2000; repeat: true; running: root.monitoring; onTriggered: root.refresh() }
    Component.onCompleted: { clearQr(); refresh() }
}
