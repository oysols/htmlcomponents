# htmlcomponents

```
pip install "git+https://github.com/oysols/htmlcomponents"
```

```
from htmlcomponents.components import html

html.doctype(
    html.html(
        html.head(
            html.title("Hello world!"),
        ),
        html.body(
            html.h1(style={"color": "red"})("Hello World!"),
            html.img(src="logo.jpg"),
            html.p("Text"),
        ),
    )
).render_html()
```
