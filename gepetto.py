from gepetto.config import GepettoConfig
from gepetto.models.base import get_model


def PLUGIN_ENTRY():
    GepettoConfig("config.ini").load(get_model)  # Loads configuration data from gepetto/config.ini

    # Only import the rest of the code after the translations have been loaded, because the _ function (gettext)
    # needs to have been imported in the namespace first.
    from gepetto.ida.ui import GepettoPlugin
    return GepettoPlugin()
