from __future__ import annotations

from dataclasses import dataclass
from html import escape
from typing import Dict, List, Self


@dataclass
class Component:
    """HTML Component base class for building HTML documents in Python

    `children` are html escaped
        DangerouslySetInnerHTML can be used to bypass html escaping

    `attrs` is NOT secure against injection attacks
        attrs with underscores '_' will be replaced with dashes '-'
        'class_' attr will be rendered as 'class'
        attrs can be valueless by setting them to None
        attrs are not validated to be valid

    `style` is NOT secure against injection attacks
        style is handled as a dictionary and converted to inline styles in the html tag
        styles are not validated to be valid

    Example:
    >>> class p(Component): pass
    >>> p(id="mytext", style={"color": "red"})(
    ...     "Hello World!"
    ... ).render_html()
    '<p id="mytext" style="color: red">Hello World!</p>'
    """

    children: List[Component | str | None]
    style: Dict[str, str]
    attrs: Dict[str, str | None]

    def __init__(
        self,
        *children: Component | str | None,
        style: Dict[str, str] = {},
        **attrs: str | None,
    ) -> None:
        self.children = list(children)
        self.attrs = attrs.copy()
        self.style = style.copy()

    def __call__(self, *children: Component | str | None) -> Self:
        if self.children:
            raise Exception("Component allready has children")
        self.children = list(children)
        return self

    def __repr__(self) -> str:
        return f"Component<{self.__class__.__name__}>"

    def render_html(self, indent: int = 0) -> str:
        return "\n".join(self.render_component(indent))

    def render_component(self, indent: int = 0) -> List[str]:
        # Handle special attrs
        attrs = {}
        special_replacements = {"class_": "class"}
        for k, v in self.attrs.items():
            if replacement := special_replacements.get(k):
                k = replacement
            k = k.replace("_", "-")
            attrs[k] = v
        # Convert style dict to inline css
        if self.style:
            attrs["style"] = "; ".join([f"{k}: {v}" for k, v in self.style.items()])
        # Generate opening tag string
        attrs_string = " ".join(
            # If value is None do not output equal sign or value
            f'{escape(key)}="{escape(value)}"' if value is not None else f"{escape(key)}"
            for key, value in attrs.items()
        )
        name = self.__class__.__name__.replace("_", "-")
        first_line = " " * indent + f"<{name}{' ' + attrs_string if attrs_string else ''}>"
        # Void element
        if isinstance(self, VoidComponent):
            return [first_line]
        # Inline empty
        if not self.children:
            return [first_line + f"</{name}>"]
        # Inline single string children
        if (
            len(self.children) == 1
            and isinstance(self.children[0], str)
            and not isinstance(self.children[0], DangerouslySetInnerHTML)
        ):
            return [first_line + escape(self.children[0]) + f"</{name}>"]
        lines = [first_line]
        lines += render_components(self.children, indent + 2)
        lines += [" " * indent + f"</{name}>"]
        return lines


def render_components(components: List[Component | str | None], indent: int = 0) -> List[str]:
    lines = []
    for component in components:
        if isinstance(component, DangerouslySetInnerHTML):
            lines += [" " * indent + component]
        elif isinstance(component, str):
            lines += [" " * indent + escape(component)]
        elif component is None:
            continue
        elif isinstance(component, Component):
            lines += component.render_component(indent)
        else:
            raise Exception(f"Cannot render unexpected type: {type(component)}")
    return lines


class DangerouslySetInnerHTML(str):
    pass


class VoidComponent(Component):
    # self-closing tags / void elements / void components
    # https://developer.mozilla.org/en-US/docs/Glossary/Void_element
    pass


# fmt: off
# ruff: noqa: E701
# Namespace to make imports/usage easier
class html:
    """HTML Components"""
    # Void elements
    class area(VoidComponent): pass
    class base(VoidComponent): pass
    class br(VoidComponent): pass
    class col(VoidComponent): pass
    class embed(VoidComponent): pass
    class hr(VoidComponent): pass
    class img(VoidComponent): pass
    class input(VoidComponent): pass
    class link(VoidComponent): pass
    class meta(VoidComponent): pass
    class param(VoidComponent): pass
    class source(VoidComponent): pass
    class track(VoidComponent): pass
    class wbr(VoidComponent): pass

    # All HTML tags elements (without void elements)
    # https://developer.mozilla.org/en-US/docs/Web/HTML/Element
    class a(Component): pass
    class abbr(Component): pass
    class address(Component): pass
    class article(Component): pass
    class aside(Component): pass
    class audio(Component): pass
    class b(Component): pass
    class bdi(Component): pass
    class bdo(Component): pass
    class blockquote(Component): pass
    class body(Component): pass
    class button(Component): pass
    class canvas(Component): pass
    class caption(Component): pass
    class cite(Component): pass
    class code(Component): pass
    class colgroup(Component): pass
    class data(Component): pass
    class datalist(Component): pass
    class dd(Component): pass
    class del_(Component): pass
    class details(Component): pass
    class dfn(Component): pass
    class dialog(Component): pass
    class div(Component): pass
    class dl(Component): pass
    class dt(Component): pass
    class em(Component): pass
    class fieldset(Component): pass
    class figcaption(Component): pass
    class figure(Component): pass
    class footer(Component): pass
    class form(Component): pass
    class h1(Component): pass
    class h2(Component): pass
    class h3(Component): pass
    class h4(Component): pass
    class h5(Component): pass
    class h6(Component): pass
    class head(Component): pass
    class header(Component): pass
    class hgroup(Component): pass
    class html(Component): pass
    class i(Component): pass
    class iframe(Component): pass
    class ins(Component): pass
    class kbd(Component): pass
    class label(Component): pass
    class legend(Component): pass
    class li(Component): pass
    class main(Component): pass
    class map(Component): pass
    class mark(Component): pass
    class menu(Component): pass
    class meter(Component): pass
    class nav(Component): pass
    class noscript(Component): pass
    class object(Component): pass
    class ol(Component): pass
    class optgroup(Component): pass
    class option(Component): pass
    class output(Component): pass
    class p(Component): pass
    class picture(Component): pass
    class pre(Component): pass
    class progress(Component): pass
    class q(Component): pass
    class rp(Component): pass
    class rt(Component): pass
    class ruby(Component): pass
    class s(Component): pass
    class samp(Component): pass
    class script(Component): pass
    class search(Component): pass
    class section(Component): pass
    class select(Component): pass
    class slot(Component): pass
    class small(Component): pass
    class span(Component): pass
    class strong(Component): pass
    class style(Component): pass
    class sub(Component): pass
    class summary(Component): pass
    class sup(Component): pass
    class table(Component): pass
    class tbody(Component): pass
    class td(Component): pass
    class template(Component): pass
    class textarea(Component): pass
    class tfoot(Component): pass
    class th(Component): pass
    class thead(Component): pass
    class time(Component): pass
    class title(Component): pass
    class tr(Component): pass
    class u(Component): pass
    class ul(Component): pass
    class var(Component): pass
    class video(Component): pass
    class xmp(Component): pass

    # Custom handling for special doctype component
    class doctype(Component):
        def render_component(self, indent: int = 0) -> List[str]:
            return ["<!DOCTYPE html>"] + render_components(self.children, indent)

    # Svg subset
    class svg(Component): pass
    class path(Component): pass
    class circle(Component): pass
    class g(Component): pass
    class defs(Component): pass
    class clippath(Component): pass
    class rect(Component): pass
# fmt: on


def html_doc_template(*body: Component | str | None) -> Component:
    """Simple html document example"""
    return html.doctype(
        html.html(
            html.head(
                html.title(),
                html.meta(charset="utf-8"),
                html.link(rel="icon", href="noop://"),
                html.style("*{box-sizing: border-box;} body{margin: 0; padding: 0;}"),
            ),
            html.body(*body),
        )
    )


if __name__ == "__main__":
    # Simple example
    print(
        html_doc_template(
            html.h1(style={"color": "red", "font-family": "verdana", "background-color": "pink"})(
                "Hello, World!",
            )
        ).render_html()
    )
