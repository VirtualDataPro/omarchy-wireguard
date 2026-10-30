import QtQuick
import qs.Commons
import qs.Commons as Commons
import "Traffic.js" as Traffic

Column {
    id: root
    property var samples: []
    property bool available: false
    property bool active: false
    readonly property var latest: samples.length ? samples[samples.length - 1] : ({down: 0, up: 0})
    spacing: Style.space(8)
    Row {
        width: parent.width
        Text { width: parent.width / 2; text: "↓ " + Traffic.rate(root.latest.down); color: Commons.Color.accent; font.family: Style.font.family; font.pixelSize: Style.font.body }
        Text { width: parent.width / 2; horizontalAlignment: Text.AlignRight; text: "↑ " + Traffic.rate(root.latest.up); color: Commons.Color.foreground; font.family: Style.font.family; font.pixelSize: Style.font.body }
    }
    Canvas {
        id: canvas
        width: parent.width
        height: Style.space(110)
        property color downloadColor: Commons.Color.accent
        property color uploadColor: Commons.Color.foreground
        onDownloadColorChanged: requestPaint()
        onUploadColorChanged: requestPaint()
        onWidthChanged: requestPaint()
        onPaint: {
            var ctx = getContext("2d"); ctx.reset()
            var max = 1024
            root.samples.forEach(p => max = Math.max(max, p.down, p.up))
            ctx.strokeStyle = Qt.rgba(uploadColor.r, uploadColor.g, uploadColor.b, 0.12)
            ctx.lineWidth = 1
            for (var i = 0; i < 3; i++) {
                var y = 4 + (height - 8) * i / 2
                ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke()
            }
            function draw(key, color) {
                ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath()
                root.samples.forEach((p, i) => {
                    var x = width * (30 - root.samples.length + i) / 29
                    var y = height - 4 - (height - 8) * p[key] / max
                    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y)
                })
                ctx.stroke()
            }
            draw("down", downloadColor); draw("up", uploadColor)
        }
        Text {
            anchors.centerIn: parent
            visible: !root.available
            text: root.active ? "Waiting for traffic samples" : "Enable a tunnel to see live traffic"
            color: Commons.Color.foreground; opacity: 0.65
            font.family: Style.font.family; font.pixelSize: Style.font.caption
        }
    }
    Text { text: "Last 60 seconds · receive / send"; color: Commons.Color.foreground; opacity: 0.55; font.family: Style.font.family; font.pixelSize: Style.font.caption }
    onSamplesChanged: canvas.requestPaint()
}
