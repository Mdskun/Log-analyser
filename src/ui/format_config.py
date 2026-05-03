"""
Format Configuration UI Component
==================================

Provides UI for selecting and configuring log format parsing options.
Allows users to specify custom timestamp formats and other parser configurations.

Usage:
    import streamlit as st
    from src.ui.format_config import render_format_config
    
    format_name, format_config = render_format_config()
"""

import streamlit as st
from typing import Tuple, Dict, Optional, Any
from src.parsers.factory import LogParser


class FormatConfigUI:
    """UI component for log format selection and configuration."""
    
    # Format-specific configuration templates
    CONFIG_TEMPLATES = {
        "apache_modjk": {
            "description": "Apache mod_jk/Tomcat Connector Logs",
            "timestamp_formats": [
                "%a %b %d %H:%M:%S %Y",  # Sun Dec 04 04:51:14 2005
                "%b %d %H:%M:%S %Y",     # Dec 04 04:51:14 2005
                "%Y-%m-%d %H:%M:%S",     # 2005-12-04 04:51:14
            ],
            "fields": {
                "timestamp_format": {
                    "type": "selectbox",
                    "label": "Timestamp Format",
                    "options": [
                        "%a %b %d %H:%M:%S %Y (e.g., Sun Dec 04 04:51:14 2005)",
                        "%b %d %H:%M:%S %Y (e.g., Dec 04 04:51:14 2005)",
                        "%Y-%m-%d %H:%M:%S (e.g., 2005-12-04 04:51:14)",
                        "Custom format (strftime)",
                    ],
                    "help": "Select the timestamp format used in your logs",
                },
                "custom_timestamp_format": {
                    "type": "text_input",
                    "label": "Custom Timestamp Format (strftime)",
                    "placeholder": "%a %b %d %H:%M:%S %Y",
                    "help": "Use strftime codes: https://docs.python.org/3/library/datetime.html#strftime-and-strptime-format-codes",
                    "conditional": "timestamp_format == 'Custom format (strftime)'",
                },
            },
        },
        "tomcat_connector": {
            "description": "Tomcat Connector Logs",
            "timestamp_formats": [
                "%Y-%m-%d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S",
            ],
            "fields": {
                "timestamp_format": {
                    "type": "selectbox",
                    "label": "Timestamp Format",
                    "options": [
                        "%Y-%m-%d %H:%M:%S (e.g., 2024-01-15 10:30:45)",
                        "%d/%b/%Y:%H:%M:%S (e.g., 15/Jan/2024:10:30:45)",
                        "Custom format (strftime)",
                    ],
                },
            },
        },
        "custom": {
            "description": "Custom Structured Format",
            "fields": {
                "timestamp_format": {
                    "type": "selectbox",
                    "label": "Timestamp Format",
                    "options": [
                        "%Y-%m-%d %H:%M:%S",
                        "%d/%b/%Y:%H:%M:%S",
                        "Custom format",
                    ],
                },
            },
        },
    }
    
    @staticmethod
    def render() -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Render format selection and configuration UI.
        
        Returns:
            Tuple of (selected_format_name, format_config_dict)
        """
        st.subheader("📋 Log Format Configuration")
        
        # Get all format information
        format_info = LogParser.get_all_format_info()
        format_names = list(format_info.keys())
        
        # Format selection
        col1, col2 = st.columns([2, 1])
        
        with col1:
            selected_format = st.selectbox(
                "Select Log Format",
                format_names,
                format_shape="wide",
                help="Choose the format of your log files"
            )
        
        with col2:
            st.info(f"Supports Config: {format_info[selected_format].get('supports_config', False)}")
        
        # Display format description
        description = format_info[selected_format].get("description", "")
        if description:
            st.markdown(f"_{description}_")
        
        # Format-specific configuration
        format_config = None
        
        if format_info[selected_format].get("supports_config", False):
            st.markdown("---")
            st.subheader("⚙️ Format-Specific Configuration")
            
            format_config = {}
            
            if selected_format in FormatConfigUI.CONFIG_TEMPLATES:
                template = FormatConfigUI.CONFIG_TEMPLATES[selected_format]
                
                # Render configuration fields
                for field_name, field_config in template.get("fields", {}).items():
                    field_type = field_config.get("type", "text_input")
                    field_label = field_config.get("label", field_name)
                    
                    if field_type == "selectbox":
                        options = field_config.get("options", [])
                        value = st.selectbox(
                            field_label,
                            options,
                            help=field_config.get("help", ""),
                        )
                        
                        # Handle custom input for "Custom format" option
                        if "Custom" in str(value) and "timestamp_format" in field_name:
                            custom_value = st.text_input(
                                "Enter Custom Timestamp Format",
                                placeholder="%a %b %d %H:%M:%S %Y",
                                help=field_config.get("help", ""),
                            )
                            if custom_value:
                                # Map back to the actual format code
                                if "apache_modjk" in field_name or "tomcat" in selected_format:
                                    format_config["timestamp_format"] = custom_value
                        else:
                            # Extract format code from option string
                            # Format is "code (description)"
                            if " (" in value:
                                format_code = value.split(" (")[0]
                            else:
                                format_code = value
                            
                            if "timestamp_format" in field_name:
                                format_config["timestamp_format"] = format_code
        
        return selected_format, format_config


def render_format_selection_expander() -> Tuple[str, Optional[Dict[str, Any]]]:
    """
    Render format selection in an expander (for compact UI).
    
    Returns:
        Tuple of (selected_format_name, format_config_dict)
    """
    with st.expander("📋 Configure Log Format", expanded=True):
        return FormatConfigUI.render()


def show_format_examples(format_name: str) -> None:
    """
    Display example logs for a given format.
    
    Args:
        format_name: Name of the format
    """
    examples = {
        "apache_modjk": [
            "[Sun Dec 04 04:51:14 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties",
            "[Sun Dec 04 04:51:18 2005] [error] mod_jk child workerEnv in error state 6",
            "[Sun Dec 04 04:51:37 2005] [notice] jk2_init() Found child 6736 in scoreboard slot 10",
            "[Sun Dec 04 04:51:38 2005] [notice] jk2_init() Found child 6733 in scoreboard slot 7",
        ],
        "tomcat_connector": [
            "2024-01-15 10:30:45.123 [INFO] Tomcat started on port 8080",
            "2024-01-15 10:30:46.456 [WARN] Slow request detected: 5000ms",
            "2024-01-15 10:30:47.789 [ERROR] Connection reset by peer",
        ],
        "custom": [
            "[2024-01-15 10:30:45] [INFO] [api] Request started",
            "[2024-01-15 10:30:46] [ERROR] [db] Connection failed",
            "[2024-01-15 10:30:47] [WARN] [cache] TTL expired",
        ],
        "apache": [
            '192.168.1.1 - - [15/Jan/2024:10:30:45 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
            '192.168.1.2 - - [15/Jan/2024:10:30:46 +0000] "POST /api/login HTTP/1.1" 401 567 "-" "curl/7.68.0"',
        ],
        "syslog": [
            "Jan 15 10:30:45 server nginx[1234]: error opening file /var/log/error.log",
            "Jan 15 10:30:46 server systemd[1]: Started Application Service",
        ],
    }
    
    if format_name in examples:
        st.markdown("**Example Logs:**")
        for example in examples[format_name]:
            st.code(example, language="log")


def render_format_help() -> None:
    """Render help/documentation for log formats."""
    
    st.info("""
    ### 📚 Log Format Guide
    
    **Choosing the Right Format:**
    1. Look at the timestamp format in your logs
    2. Check the overall log structure
    3. Select the matching format from the dropdown
    
    **Custom Timestamp Formats:**
    - Use Python strftime codes: `%Y` = year, `%m` = month, `%d` = day, etc.
    - Example: `%a %b %d %H:%M:%S %Y` → `Sun Dec 04 04:51:14 2005`
    - See [Python docs](https://docs.python.org/3/library/datetime.html#strftime-and-strptime-format-codes)
    
    **If your format isn't listed:**
    - Use "generic" format - it will attempt to parse with heuristics
    - Consider using "custom" format with a custom timestamp format
    """)


__all__ = [
    "FormatConfigUI",
    "render_format_selection_expander",
    "show_format_examples",
    "render_format_help",
]
