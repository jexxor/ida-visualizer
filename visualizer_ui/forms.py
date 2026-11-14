"""Auxiliary IDA dock forms."""

import ida_kernwin

class ByteInspectorForm(ida_kernwin.PluginForm):
    def __init__(self, panel):
        super().__init__()
        self.panel = panel

    def OnCreate(self, form):
        self.panel._create_inspector_widget(self.FormToPyQtWidget(form))

    def OnClose(self, form):
        self.panel._inspector_closed(self)


class ByteDiffForm(ida_kernwin.PluginForm):
    def __init__(self, panel):
        super().__init__()
        self.panel = panel

    def OnCreate(self, form):
        self.panel._create_diff_widget(self.FormToPyQtWidget(form))

    def OnClose(self, form):
        self.panel._diff_closed(self)


class FindingsForm(ida_kernwin.PluginForm):
    def __init__(self, panel):
        super().__init__()
        self.panel = panel

    def OnCreate(self, form):
        self.panel._create_findings_widget(self.FormToPyQtWidget(form))

    def OnClose(self, form):
        self.panel._findings_closed(self)
