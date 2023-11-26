import idaapi
import ida_hexrays

from .handlers import ExplainHandler, RenameHandler, SwapModelHandler
from ..config import GepettoConfig

config = GepettoConfig()

# =============================================================================
# Setup the context menu and hotkey in IDA
# =============================================================================

class GepettoPlugin(idaapi.plugin_t):
    flags = 0
    explain_action_name = "gepetto:explain_function"
    explain_menu_path = "Edit/Gepetto/" + _("Explain function")
    rename_action_name = "gepetto:rename_function"
    rename_menu_path = "Edit/Gepetto/" + _("Rename variables")

    # Model selection menu
    select_model_actions = [
        {
            "action_name": "gepetto:select_gpt35",
            "menu_path": "gepetto:select_gpt4"
        },
        {
            "action_name": "Edit/Gepetto/" + _("Select model") + "/gpt-3.5-turbo",
            "menu_path": "Edit/Gepetto/" + _("Select model") + "/gpt-4-turbo"
        },
    ]

    wanted_name = 'Gepetto'
    wanted_hotkey = ''
    comment = _("Uses {model} to enrich the decompiler's output").format(model=str(config.model))
    help = _("See usage instructions on GitHub")
    menu = None

    # -----------------------------------------------------------------------------

    def init(self):
        # Check whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        # Function explaining action
        explain_action = idaapi.action_desc_t(self.explain_action_name,
                                              _('Explain function'),
                                              ExplainHandler(),
                                              "Ctrl+Alt+G",
                                              _('Use {model} to explain the currently selected function').format(
                                                  model=str(config.model)),
                                              201)
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)

        # Variable renaming action
        rename_action = idaapi.action_desc_t(self.rename_action_name,
                                             _('Rename variables'),
                                             RenameHandler(),
                                             "Ctrl+Alt+R",
                                             _("Use {model} to rename this function's variables").format(
                                                 model=str(config.model)),
                                             201)
        idaapi.register_action(rename_action)
        idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)

        self.generate_plugin_select_menu()

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        return idaapi.PLUGIN_KEEP

    # -----------------------------------------------------------------------------

    def generate_plugin_select_menu(self):
        for action in self.select_model_actions:
            selected = str(config.model) == action["action_name"]
            select_action = idaapi.action_desc_t(action["action_name"],
                                                    action["action_name"],
                                                    SwapModelHandler(action["action_name"], action["action_name"], selected),
                                                    "",
                                                    "",
                                                    208 if selected else 0)
            idaapi.register_action(select_action)
            idaapi.attach_action_to_menu(action["menu_path"], action["action_name"], idaapi.SETMENU_APP)

    def run(self, arg):
        pass

    # -----------------------------------------------------------------------------

    def term(self):
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)

        for action in self.select_model_actions:
            idaapi.detach_action_from_menu(action["menu_path"], action["action_name"])

        if self.menu:
            self.menu.unhook()
        return

# -----------------------------------------------------------------------------

class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, GepettoPlugin.explain_action_name, "Gepetto/")
            idaapi.attach_action_to_popup(form, popup, GepettoPlugin.rename_action_name, "Gepetto/")
