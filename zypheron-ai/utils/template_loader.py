"""
Jinja2 Template Loader for Zypheron AI

Provides centralized template loading and rendering following
the Strix pattern for modular prompt templates.
"""

from pathlib import Path
from typing import Dict, List, Optional, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape, Template
from jinja2.sandbox import SandboxedEnvironment
import logging

logger = logging.getLogger(__name__)


class TemplateLoader:
    """Centralized template loader for Jinja2"""

    def __init__(self, base_path: Optional[Path] = None):
        """Initialize template loader

        Args:
            base_path: Base path for templates (defaults to zypheron-ai/)
        """
        if base_path is None:
            base_path = Path(__file__).parent.parent

        self.base_path = base_path
        self.templates_dir = base_path / "templates"
        self.prompts_dir = base_path / "prompts"

        # Ensure directories exist
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.prompts_dir.mkdir(parents=True, exist_ok=True)

        # Create Jinja2 environments
        self.template_env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )

        # SECURITY (H-05): prompt templates receive context from scan output and
        # other external/tool data. A plain Environment allows SSTI -> arbitrary
        # code execution. Use SandboxedEnvironment, which blocks access to unsafe
        # attributes/methods during rendering. autoescape stays False (prompts
        # are LLM text, not HTML), but the sandbox neutralises payloads.
        self.prompt_env = SandboxedEnvironment(
            loader=FileSystemLoader(self.prompts_dir),
            autoescape=False,  # Don't escape prompts
            trim_blocks=True,
            lstrip_blocks=True
        )

        # Add custom filters
        self._register_custom_filters()

        logger.info(f"TemplateLoader initialized: templates={self.templates_dir}, prompts={self.prompts_dir}")

    def _register_custom_filters(self):
        """Register custom Jinja2 filters"""

        def format_severity(severity: str) -> str:
            """Get color code for severity level"""
            colors = {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745'
            }
            return colors.get(str(severity).lower(), '#6c757d')

        def format_timestamp(dt) -> str:
            """Format datetime for reports"""
            if dt is None:
                return "N/A"
            if hasattr(dt, 'strftime'):
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            return str(dt)

        def status_class(status_value: str) -> str:
            """Convert status enum value to CSS class"""
            return str(status_value).replace('_', '-')

        # Register filters for both environments
        self.template_env.filters['severity_color'] = format_severity
        self.template_env.filters['timestamp'] = format_timestamp
        self.template_env.filters['status_class'] = status_class

        self.prompt_env.filters['timestamp'] = format_timestamp

    def render_template(
        self,
        template_name: str,
        context: Dict[str, Any]
    ) -> str:
        """Render a template from templates/ directory

        Args:
            template_name: Template filename (e.g., 'compliance/report.html.jinja')
            context: Dictionary of variables to pass to template

        Returns:
            Rendered template string

        Raises:
            Exception: If template not found or rendering fails
        """
        try:
            template = self.template_env.get_template(template_name)
            rendered = template.render(**context)
            logger.debug(f"Successfully rendered template: {template_name}")
            return rendered
        except Exception as e:
            logger.error(f"Failed to render template {template_name}: {e}")
            raise

    def render_prompt(
        self,
        prompt_name: str,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Render a prompt from prompts/ directory

        Args:
            prompt_name: Prompt filename (e.g., 'vulnerabilities/xss.jinja')
            context: Optional variables to pass to prompt

        Returns:
            Rendered prompt string

        Raises:
            Exception: If prompt not found or rendering fails
        """
        try:
            template = self.prompt_env.get_template(prompt_name)
            rendered = template.render(**(context or {}))
            logger.debug(f"Successfully rendered prompt: {prompt_name}")
            return rendered
        except Exception as e:
            logger.error(f"Failed to render prompt {prompt_name}: {e}")
            raise

    def load_prompt_modules(
        self,
        module_names: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """Load multiple prompt modules (Strix pattern)

        Args:
            module_names: List of module names (e.g., ['xss', 'sql_injection'])
            context: Optional context for rendering

        Returns:
            Dictionary mapping module name to rendered content
        """
        modules = {}
        available = self.get_available_prompt_modules()

        for module_name in module_names:
            try:
                # Find module path
                module_path = self._find_prompt_module(module_name, available)

                if module_path:
                    content = self.render_prompt(module_path, context)
                    var_name = module_name.split('/')[-1]
                    modules[var_name] = content
                    logger.info(f"Loaded prompt module: {module_name}")
                else:
                    logger.warning(f"Prompt module not found: {module_name}")

            except Exception as e:
                logger.warning(f"Failed to load module {module_name}: {e}")

        return modules

    def get_available_prompt_modules(self) -> Dict[str, List[str]]:
        """Get available prompt modules organized by category

        Returns:
            Dictionary mapping category to list of module names
        """
        available = {}

        if not self.prompts_dir.exists():
            return available

        for category_dir in self.prompts_dir.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith('__'):
                modules = [
                    f.stem for f in category_dir.glob('*.jinja')
                ]
                if modules:
                    available[category_dir.name] = sorted(modules)

        return available

    def _find_prompt_module(
        self,
        module_name: str,
        available: Dict[str, List[str]]
    ) -> Optional[str]:
        """Find full path for a prompt module

        Args:
            module_name: Module name (can be 'name' or 'category/name')
            available: Available modules dict

        Returns:
            Full path to template or None if not found
        """
        # If already a path
        if '/' in module_name:
            candidate = f"{module_name}.jinja"
            if (self.prompts_dir / candidate).exists():
                return candidate

        # Search in categories
        for category, modules in available.items():
            if module_name in modules:
                return f"{category}/{module_name}.jinja"

        # Check root level
        candidate = f"{module_name}.jinja"
        if (self.prompts_dir / candidate).exists():
            return candidate

        return None

    def template_exists(self, template_name: str) -> bool:
        """Check if a template exists

        Args:
            template_name: Template path (e.g., 'compliance/pci_dss.html.jinja')

        Returns:
            True if template exists
        """
        return (self.templates_dir / template_name).exists()

    def prompt_exists(self, prompt_name: str) -> bool:
        """Check if a prompt exists

        Args:
            prompt_name: Prompt path (e.g., 'vulnerabilities/xss.jinja')

        Returns:
            True if prompt exists
        """
        return (self.prompts_dir / prompt_name).exists()


# Global singleton instance
_loader: Optional[TemplateLoader] = None


def get_template_loader() -> TemplateLoader:
    """Get global template loader instance

    Returns:
        TemplateLoader singleton
    """
    global _loader
    if _loader is None:
        _loader = TemplateLoader()
    return _loader


def reset_template_loader():
    """Reset global template loader (useful for testing)"""
    global _loader
    _loader = None
