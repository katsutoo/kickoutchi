"""Minimal bounded ANSI screen reconstruction for release TUI evidence."""

from __future__ import annotations


def render_terminal_screen(data: bytes, rows: int, columns: int) -> str:
    if not 1 <= rows <= 200 or not 1 <= columns <= 500:
        raise ValueError("terminal dimensions are out of bounds")
    text = data.decode("utf-8", "replace")
    screen = [[" "] * columns for _ in range(rows)]
    row = column = 0
    saved = (0, 0)
    index = 0

    def parameter_values(value: str) -> list[int]:
        value = value.lstrip("?<>=")
        if not value:
            return [0]
        result = []
        for item in value.split(";"):
            try:
                result.append(int(item or "0"))
            except ValueError:
                result.append(0)
        return result

    while index < len(text):
        character = text[index]
        if character == "\x1b":
            if index + 1 >= len(text):
                break
            following = text[index + 1]
            if following == "[":
                end = index + 2
                while end < len(text) and not "@" <= text[end] <= "~":
                    end += 1
                if end >= len(text):
                    break
                values = parameter_values(text[index + 2:end])
                command = text[end]
                amount = max(values[0], 1)
                if command in "Hf":
                    row = min(max((values[0] or 1) - 1, 0), rows - 1)
                    column = min(max(((values[1] if len(values) > 1 else 1) or 1) - 1, 0), columns - 1)
                elif command == "A":
                    row = max(row - amount, 0)
                elif command == "B":
                    row = min(row + amount, rows - 1)
                elif command == "C":
                    column = min(column + amount, columns - 1)
                elif command == "D":
                    column = max(column - amount, 0)
                elif command == "G":
                    column = min(max(amount - 1, 0), columns - 1)
                elif command == "d":
                    row = min(max(amount - 1, 0), rows - 1)
                elif command == "J" and values[0] in {2, 3}:
                    screen = [[" "] * columns for _ in range(rows)]
                    row = column = 0
                elif command == "K":
                    if values[0] == 1:
                        screen[row][: column + 1] = [" "] * (column + 1)
                    elif values[0] == 2:
                        screen[row] = [" "] * columns
                    else:
                        screen[row][column:] = [" "] * (columns - column)
                elif command == "X":
                    end_column = min(column + amount, columns)
                    screen[row][column:end_column] = [" "] * (end_column - column)
                elif command == "s":
                    saved = (row, column)
                elif command == "u":
                    row, column = saved
                index = end + 1
                continue
            if following == "]":
                end = index + 2
                while end < len(text) and text[end] != "\a" and not text.startswith("\x1b\\", end):
                    end += 1
                index = end + (2 if text.startswith("\x1b\\", end) else 1)
                continue
            if following == "7":
                saved = (row, column)
            elif following == "8":
                row, column = saved
            index += 2
            continue
        if character == "\r":
            column = 0
        elif character == "\n":
            row = min(row + 1, rows - 1)
        elif character == "\b":
            column = max(column - 1, 0)
        elif character == "\t":
            column = min((column // 8 + 1) * 8, columns - 1)
        elif character >= " ":
            screen[row][column] = character
            column += 1
            if column >= columns:
                column = columns - 1
        index += 1
    return "\n".join("".join(line).rstrip() for line in screen)
