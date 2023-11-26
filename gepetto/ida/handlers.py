import functools
import json
import re
import textwrap

import idaapi
import ida_hexrays
import idc

from ..models import get_model
from ..config import GepettoConfig

config = GepettoConfig()

def comment_callback(address, view, response):
    """
    Callback that sets a comment at the given address.
    :param address: The address of the function to comment
    :param view: A handle to the decompiler window
    :param response: The comment to add
    """
    response = "\n".join(textwrap.wrap(response, 80, replace_whitespace=False))

    # Add the response as a comment in IDA, but preserve any existing non-Gepetto comment
    comment = idc.get_func_cmt(address, 0)
    comment = re.sub(r'----- ' + _("Comment generated by Gepetto") + ' -----.*?----------------------------------------',
                     r"",
                     comment,
                     flags=re.DOTALL)

    idc.set_func_cmt(address, '----- ' + _("Comment generated by Gepetto") +
                     f" -----\n\n"
                     f"{response.strip()}\n\n"
                     f"----------------------------------------\n\n"
                     f"{comment.strip()}", 0)
    # Refresh the window so the comment is displayed properly
    if view:
        view.refresh_view(False)
    print(_("{model} query finished!").format(model=str(config.model)))


# -----------------------------------------------------------------------------

class ExplainHandler(idaapi.action_handler_t):
    """
    This handler is tasked with querying the model for an explanation of the
    given function. Once the reply is received, it is added as a function
    comment.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        config.model.query_model_async(
            _("Can you explain what the following C function does and suggest a better name for "
            "it?\n{decompiler_output}").format(decompiler_output=str(decompiler_output)),
            functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------------

def rename_callback(address, view, response, retries=0):
    """
    Callback that extracts a JSON array of old names and new names from the
    response and sets them in the pseudocode.
    :param address: The address of the function to work on
    :param view: A handle to the decompiler window
    :param response: The response from the model
    :param retries: The number of times that we received invalid JSON
    """
    j = re.search(r"\{[^}]*?\}", response)
    if not j:
        if retries >= 3:  # Give up obtaining the JSON after 3 times.
            print(_("Could not obtain valid data from the model, giving up. Dumping the response for manual import:"))
            print(response)
            return
        print(_("Cannot extract valid JSON from the response. Asking the model to fix it..."))
        config.model.query_model_async(
            _("The JSON document provided in this response is invalid. Can you fix it?\n"
            "{response}").format(response=response),
            functools.partial(rename_callback,
                              address=address,
                              view=view,
                              retries=retries + 1))
        return
    try:
        names = json.loads(j.group(0))
    except json.decoder.JSONDecodeError:
        if retries >= 3:  # Give up fixing the JSON after 3 times.
            print(_("Could not obtain valid data from the model, giving up. Dumping the response for manual import:"))
            print(response)
            return
        print(_("The JSON document returned is invalid. Asking the model to fix it..."))
        config.model.query_model_async(
            _("Please fix the following JSON document:\n{json}").format(json=j.group(0)),
            functools.partial(rename_callback,
                              address=address,
                              view=view,
                              retries=retries + 1))
        return

    # The rename function needs the start address of the function
    function_addr = idaapi.get_func(address).start_ea

    replaced = []
    for n in names:
        if idaapi.IDA_SDK_VERSION < 760:
            lvars = {lvar.name: lvar for lvar in view.cfunc.lvars}
            if n in lvars:
                if view.rename_lvar(lvars[n], names[n], True):
                    replaced.append(n)
        else:
            if ida_hexrays.rename_lvar(function_addr, n, names[n]):
                replaced.append(n)

    # Update possible names left in the function comment
    comment = idc.get_func_cmt(address, 0)
    if comment and len(replaced) > 0:
        for n in replaced:
            comment = re.sub(r'\b%s\b' % n, names[n], comment)
        idc.set_func_cmt(address, comment, 0)

    # Refresh the window to show the new names
    if view:
        view.refresh_view(True)
    print(_("{model} query finished! {replaced} variable(s) renamed.").format(model=str(config.model),
                                                                              replaced=len(replaced)))

# -----------------------------------------------------------------------------

class RenameHandler(idaapi.action_handler_t):
    """
    This handler requests new variable names from the model and updates the
    decompiler's output.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        config.model.query_model_async(
            _("Analyze the following C function:\n{decompiler_output}"
            "\nSuggest better variable names, reply with a JSON array where keys are the original"
            " names and values are the proposed names. Do not explain anything, only print the "
            "JSON dictionary.").format(decompiler_output=str(decompiler_output)),
            functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------------

class SwapModelHandler(idaapi.action_handler_t):
    """
    This handler replaces the model currently in use with another one selected by the user,
    and updates the configuration.
    """
    def __init__(self, new_model, plugin):
        self.new_model = new_model
        self.plugin = plugin

    def activate(self, ctx):
        config.model = get_model(self.new_model)
        config.update("Gepetto", "MODEL", self.new_model)
        # Refresh the menus to reflect which model is currently selected.
        self.plugin.generate_plugin_select_menu()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS