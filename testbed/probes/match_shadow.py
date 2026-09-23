# `case OUT:` is a capture: it binds OUT. Any binding besides the module's own makes OUT no
# constant, so the function body writing to it knows nothing of where it points.
OUT = "out/match.txt"


def write() -> None:
    open(OUT, "w").write("x\n")


def classify(x: str) -> str:
    match x:
        case "a":
            return "a"
        case OUT:
            return OUT


write()
