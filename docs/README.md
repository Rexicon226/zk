## NOTE: copied from https://codeberg.org/GameBuilder202/zig-mathdoc

# `zig-mathdoc`
`zig-mathdoc` augments generated docs for zig code to enable rendering math equations.
It does this by stitching in `<link>`s to KaTeX stuff to `docs/index.html` and the necessary code to transform text in the document to rendered math in like `668` of `docs/main.js` (which is the end of the `navigate()` function).

## Usage
Usage is pretty simple:
Generate docs with whatever setup you have (`zig-mathdoc` does *not* do this for you), and then run `math.sh`.
Both `links.html` and `script.js` should be alongside `math.sh` so perhaps put these 3 files in their own folder and add that to `PATH` or something.
