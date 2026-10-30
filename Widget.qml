import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Dialogs
import QtQuick.Effects
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons
import qs.Ui

Panel {
    id: root
    moduleName: "virtualdatapro.wireguard"
    ipcTarget: moduleName
    implicitWidth: button.implicitWidth
    implicitHeight: button.implicitHeight
    property string page: "overview"
    property string importPath: ""
    property bool autoConnect: false
    readonly property var selected: vpn.profiles.find(p => p.uuid === vpn.selectedUuid) || null
    readonly property var graphSamples: vpn.history[vpn.selectedUuid] || []
    readonly property color dim: Qt.darker(Commons.Color.foreground, 1.5)

    function showOverview() { page = "overview"; vpn.clearQr(); Qt.callLater(() => keys.forceActiveFocus()) }
    function beginAdd() {
        page = "add"; importPath = ""; tunnelName.text = ""; configText.text = ""; vpn.error = ""; vpn.message = ""
    }
    function selectOffset(offset) {
        var index = vpn.profiles.findIndex(p => p.uuid === vpn.selectedUuid)
        index = Math.max(0, Math.min(vpn.profiles.length - 1, index + offset))
        if (vpn.profiles[index]) vpn.selectedUuid = vpn.profiles[index].uuid
    }
    onOpenedChanged: {
        if (opened) { vpn.refresh(); Qt.callLater(() => keys.forceActiveFocus()) }
        else { vpn.clearQr(); configText.text = ""; if (page === "qr") page = "overview" }
    }
    Service {
        id: vpn
        onDetailReady: {
            editName.text = detail.name; editAddresses.text = detail.addresses
            editDns.text = detail.dns; editMtu.text = String(detail.mtu)
            root.autoConnect = detail.autoconnect; root.page = "edit"
        }
        onCompleted: function(operation) {
            if (operation === "save" || operation === "add") { root.showOverview(); configText.text = "" }
            if (operation === "qr") {
                if (root.opened) root.page = "qr"
                else clearQr()
            }
        }
    }
    FileDialog {
        id: picker
        title: "Import WireGuard tunnel"
        nameFilters: ["WireGuard configuration (*.conf)", "All files (*)"]
        onAccepted: {
            root.importPath = decodeURIComponent(selectedFile.toString().replace(/^file:\/\//, ""))
            if (!tunnelName.text) tunnelName.text = root.importPath.split('/').pop().replace(/\.conf$/, "")
            root.open()
        }
        onRejected: root.open()
    }
    BarIconButton {
        id: button
        anchors.fill: parent
        bar: root.bar
        iconComponent: Component {
            Image {
                source: Qt.resolvedUrl("assets/wireguard.svg")
                sourceSize.width: 64; sourceSize.height: 64
                fillMode: Image.PreserveAspectFit
                layer.enabled: !vpn.active
                layer.effect: MultiEffect {
                    // Normalize the red artwork to white before applying the bar colour.
                    contrast: -1
                    brightness: 0.5
                    colorization: 1
                    colorizationColor: button.foreground
                }
            }
        }
        onPressed: function(buttonCode) { root.toggle() }
    }
    KeyboardPanel {
        id: popup
        owner: root; bar: root.bar; anchorItem: button
        open: root.opened; focusTarget: keys
        contentWidth: popup.fittedContentWidth(Style.space(420))
        contentHeight: popup.fittedContentHeight(content.implicitHeight, Style.space(680))
        PanelKeyCatcher {
            id: keys
            anchors.fill: parent
            blocked: root.page === "add" || root.page === "edit"
            onCloseRequested: { if (root.page === "overview") root.close(); else root.showOverview() }
            onTabRequested: function(direction) { root.switchPanel(direction) }
            onMoveRequested: function(dx, dy) { root.selectOffset(dy) }
            onActivateRequested: vpn.toggle(root.selected)
            onTextKey: function(t) { if (t.toLowerCase() === "r") vpn.refresh() }
            Flickable {
                id: flick
                anchors.fill: parent
                clip: true
                contentHeight: content.implicitHeight; contentWidth: width
                boundsBehavior: Flickable.StopAtBounds
                Controls.ScrollBar.vertical: Controls.ScrollBar {}
                ColumnLayout {
                    id: content
                    width: flick.width
                    spacing: Style.space(16)
                    PanelHero {
                        Layout.fillWidth: true
                        title: "WireGuard"
                        meta: vpn.busy ? "Working…" : vpn.active ? "Encrypted tunnels active" : "Your tunnels, within reach"
                        iconComponent: Component {
                            Image {
                                width: Style.font.display; height: Style.font.display
                                source: Qt.resolvedUrl("assets/wireguard.svg")
                                sourceSize.width: 96; sourceSize.height: 96
                                fillMode: Image.PreserveAspectFit
                            }
                        }
                        trailingControl: Component {
                            PanelActionButton { iconText: root.page === "overview" ? "󰐕" : "󰌍"; tooltipText: root.page === "overview" ? "Add tunnel" : "Back"; enabled: !vpn.busy; onClicked: root.page === "overview" ? root.beginAdd() : root.showOverview() }
                        }
                    }
                    Text {
                        Layout.fillWidth: true; visible: vpn.error !== "" || vpn.message !== ""
                        text: vpn.error || vpn.message; textFormat: Text.PlainText; wrapMode: Text.Wrap
                        color: vpn.error ? Commons.Color.urgent : Commons.Color.foreground
                        font.family: Style.font.family; font.pixelSize: Style.font.caption
                    }
                    ColumnLayout {
                        visible: root.page === "overview"
                        Layout.fillWidth: true; spacing: Style.space(12)
                        PanelSectionHeader { text: "TUNNELS" }
                        Text {
                            Layout.fillWidth: true; visible: !vpn.profiles.length
                            text: "Add a WireGuard configuration to get started. Imported tunnels stay disabled until you enable them."
                            wrapMode: Text.Wrap; color: root.dim; font.family: Style.font.family; font.pixelSize: Style.font.body
                        }
                        Repeater {
                            model: vpn.profiles
                            delegate: CursorSurface {
                                id: tunnelRow
                                required property var modelData
                                required property int index
                                Layout.fillWidth: true; implicitHeight: Style.space(58)
                                hasCursor: vpn.selectedUuid === modelData.uuid
                                current: modelData.active
                                MouseArea { anchors.fill: parent; onClicked: vpn.selectedUuid = tunnelRow.modelData.uuid }
                                RowLayout {
                                    anchors.fill: parent; anchors.margins: Style.space(8); spacing: Style.space(10)
                                    Rectangle { width: Style.space(6); height: width; radius: width / 2; color: tunnelRow.modelData.active ? Commons.Color.accent : root.dim }
                                    ColumnLayout {
                                        Layout.fillWidth: true; spacing: Style.space(3)
                                        Text { Layout.fillWidth: true; text: tunnelRow.modelData.name; textFormat: Text.PlainText; elide: Text.ElideRight; color: Commons.Color.foreground; font.family: Style.font.family; font.pixelSize: Style.font.body }
                                        Text { text: tunnelRow.modelData.active ? "Active · " + tunnelRow.modelData.device : tunnelRow.modelData.state; textFormat: Text.PlainText; color: root.dim; font.family: Style.font.family; font.pixelSize: Style.font.caption }
                                    }
                                    ToggleSwitch { checked: tunnelRow.modelData.active; busy: vpn.busy; onToggled: { vpn.selectedUuid = tunnelRow.modelData.uuid; vpn.toggle(tunnelRow.modelData) } }
                                }
                            }
                        }
                        RowLayout {
                            visible: root.selected !== null; Layout.fillWidth: true; spacing: Style.space(6)
                            Button { text: "Switch here"; iconText: "󰁔"; enabled: !vpn.busy && root.selected !== null && !root.selected.active; onClicked: vpn.run("switch", vpn.selectedUuid) }
                            Item { Layout.fillWidth: true }
                            PanelActionButton { iconText: "󰒓"; tooltipText: "Configure / rename"; enabled: !vpn.busy; onClicked: vpn.run("details", vpn.selectedUuid) }
                            PanelActionButton { iconText: "󰐲"; tooltipText: "Export QR code"; enabled: !vpn.busy; onClicked: { root.page = "qrConfirm"; vpn.error = "" } }
                        }
                        Button { visible: !vpn.profiles.length; text: "Add tunnel"; iconText: "󰐕"; bordered: true; focusable: true; onClicked: root.beginAdd() }
                        PanelSeparator { Layout.fillWidth: true }
                        PanelSectionHeader { text: root.selected ? "TRAFFIC · " + root.selected.name : "TUNNEL TRAFFIC" }
                        TrafficGraph { Layout.fillWidth: true; samples: root.graphSamples; active: !!root.selected && root.selected.active; available: active && !!root.selected.counters && samples.length > 1 }
                        Text { Layout.fillWidth: true; text: "Unexpected tunnel drops appear as desktop notifications."; wrapMode: Text.Wrap; color: root.dim; font.family: Style.font.family; font.pixelSize: Style.font.caption }
                    }
                    ColumnLayout {
                        visible: root.page === "add"; Layout.fillWidth: true; spacing: Style.space(10)
                        PanelSectionHeader { text: "ADD TUNNEL" }
                        TextField { id: tunnelName; Layout.fillWidth: true; placeholderText: "Tunnel name"; enabled: !vpn.busy }
                        RowLayout {
                            Layout.fillWidth: true
                            Button { text: "Choose .conf file"; iconText: "󰉋"; bordered: true; focusable: true; enabled: !vpn.busy; onClicked: picker.open() }
                            Button { visible: root.importPath !== ""; text: "Clear"; enabled: !vpn.busy; onClicked: root.importPath = "" }
                        }
                        Text { Layout.fillWidth: true; visible: root.importPath !== ""; text: root.importPath; textFormat: Text.PlainText; elide: Text.ElideMiddle; color: Commons.Color.foreground; font.family: Style.font.family; font.pixelSize: Style.font.caption }
                        Controls.ScrollView {
                            visible: root.importPath === ""; Layout.fillWidth: true; Layout.preferredHeight: Style.space(180)
                            Controls.TextArea {
                                id: configText
                                placeholderText: "Or paste a WireGuard configuration\n\n[Interface]\nPrivateKey = …\nAddress = …\n\n[Peer]\nPublicKey = …\nAllowedIPs = …\nEndpoint = …"
                                color: Commons.Color.foreground; placeholderTextColor: root.dim
                                font.family: Style.font.family; font.pixelSize: Style.font.caption
                                textFormat: TextEdit.PlainText; wrapMode: TextEdit.Wrap; enabled: !vpn.busy
                                background: Rectangle { color: Commons.Color.background; border.color: Commons.Color.accent; border.width: 1; radius: Style.cornerRadius }
                            }
                        }
                        Text { Layout.fillWidth: true; text: "The tunnel will be saved disabled. Configuration keys are sent directly to NetworkManager."; wrapMode: Text.Wrap; color: root.dim; font.family: Style.font.family; font.pixelSize: Style.font.caption }
                        RowLayout {
                            Button { text: "Cancel"; focusable: true; enabled: !vpn.busy; onClicked: root.showOverview() }
                            Item { Layout.fillWidth: true }
                            Button { text: "Add tunnel"; bordered: true; focusable: true; enabled: !vpn.busy && tunnelName.text.trim() !== "" && (root.importPath !== "" || configText.text.trim() !== ""); onClicked: vpn.run("add", "", {name: tunnelName.text, path: root.importPath, config: configText.text}) }
                        }
                    }
                    ColumnLayout {
                        visible: root.page === "edit"; Layout.fillWidth: true; spacing: Style.space(8)
                        PanelSectionHeader { text: "CONFIGURE TUNNEL" }
                        TextField { id: editName; Layout.fillWidth: true; placeholderText: "Tunnel name"; enabled: !vpn.busy }
                        PanelSectionHeader { text: "ADDRESSES · COMMA SEPARATED" }
                        TextField { id: editAddresses; Layout.fillWidth: true; placeholderText: "10.0.0.2/32, fd00::2/128"; enabled: !vpn.busy }
                        PanelSectionHeader { text: "DNS SERVERS" }
                        TextField { id: editDns; Layout.fillWidth: true; placeholderText: "1.1.1.1, 2606:4700:4700::1111"; enabled: !vpn.busy }
                        PanelSectionHeader { text: "MTU · 0 FOR AUTOMATIC" }
                        TextField { id: editMtu; Layout.fillWidth: true; validator: IntValidator { bottom: 0; top: 65535 } enabled: !vpn.busy }
                        RowLayout {
                            Layout.fillWidth: true
                            Text { Layout.fillWidth: true; text: "Connect automatically"; color: Commons.Color.foreground; font.family: Style.font.family; font.pixelSize: Style.font.body }
                            ToggleSwitch { checked: root.autoConnect; busy: vpn.busy; onToggled: root.autoConnect = !root.autoConnect }
                        }
                        PanelSectionHeader { text: "PEERS" }
                        Repeater {
                            model: vpn.detail.peers || []
                            delegate: Text {
                                required property var modelData
                                Layout.fillWidth: true
                                text: (modelData.endpoint || "No fixed endpoint") + "\n" + modelData.allowedIPs
                                textFormat: Text.PlainText; wrapMode: Text.Wrap
                                color: root.dim; font.family: Style.font.family; font.pixelSize: Style.font.caption
                            }
                        }
                        Text { Layout.fillWidth: true; text: "Peer settings and keys are preserved. Reconnect after saving to apply changes."; wrapMode: Text.Wrap; color: root.dim; font.family: Style.font.family; font.pixelSize: Style.font.caption }
                        RowLayout {
                            Button { text: "Cancel"; focusable: true; enabled: !vpn.busy; onClicked: root.showOverview() }
                            Item { Layout.fillWidth: true }
                            Button { text: "Save changes"; bordered: true; focusable: true; enabled: !vpn.busy; onClicked: vpn.run("save", "", {uuid: vpn.detail.uuid, name: editName.text, addresses: editAddresses.text, dns: editDns.text, mtu: editMtu.text, autoconnect: root.autoConnect}) }
                        }
                    }
                    ColumnLayout {
                        visible: root.page === "qrConfirm" || root.page === "qr"; Layout.fillWidth: true; spacing: Style.space(12)
                        PanelSectionHeader { text: "EXPORT TUNNEL" }
                        Text { Layout.fillWidth: true; text: "This QR code contains the tunnel’s private key. Only show it to a device you want to give access to this tunnel."; wrapMode: Text.Wrap; color: Commons.Color.foreground; font.family: Style.font.family; font.pixelSize: Style.font.body }
                        Button { visible: root.page === "qrConfirm"; text: "Show QR code"; bordered: true; focusable: true; enabled: !vpn.busy; onClicked: vpn.run("qr", vpn.selectedUuid) }
                        Image { visible: root.page === "qr"; Layout.alignment: Qt.AlignHCenter; Layout.preferredWidth: Style.space(300); Layout.preferredHeight: Style.space(300); source: vpn.qrPath; fillMode: Image.PreserveAspectFit; smooth: false; cache: false }
                        Text { Layout.fillWidth: true; visible: root.page === "qr"; text: "Scan with the WireGuard app. The temporary image is removed when this panel closes."; wrapMode: Text.Wrap; color: root.dim; font.family: Style.font.family; font.pixelSize: Style.font.caption }
                        Button { text: "Back"; focusable: true; onClicked: root.showOverview() }
                    }
                }
            }
        }
    }
    onPageChanged: flick.contentY = 0
}
