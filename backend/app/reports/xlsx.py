"""Потоковая запись XLSX: книга openpyxl в режиме write_only держит в памяти только текущую строку.
Обычная книга хранит объект на каждую ячейку: отчёт на 100 тысяч строк и 19 столбцов занимал около 1 ГБ и минуту; потоковая запись — десятки мегабайт и в несколько раз быстрее.
Ограничения режима: ширина столбцов, закрепление строк и параметры печати задаются ДО первой строки листа, стиль — только у ячеек, переданных как `styled`."""
from __future__ import annotations

from pathlib import Path

from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell
from openpyxl.utils import get_column_letter


class Sheet:
    def __init__(self, ws):
        self.ws, self.rows = ws, 0

    def widths(self, *widths: float) -> None:
        for i, w in enumerate(widths, 1):
            self.ws.column_dimensions[get_column_letter(i)].width = w

    def freeze(self, cell: str = "A2") -> None:
        self.ws.freeze_panes = cell

    def append(self, values=(), *, font=None, fill=None, align=None, formats: dict[int, str] | None = None) -> None:
        """formats — числовой формат по номеру столбца (с нуля), например дата: стиль получают только такие ячейки."""
        if (font or fill or align or formats) and values:
            cells = []
            for i, v in enumerate(values):
                c = WriteOnlyCell(self.ws, value=v)
                if formats and i in formats and v is not None:
                    c.number_format = formats[i]
                if font:
                    c.font = font
                if fill:
                    c.fill = fill
                if align:
                    c.alignment = align
                cells.append(c)
            self.ws.append(cells)
        else:
            self.ws.append(list(values))
        self.rows += 1

    def filter(self, ncols: int) -> None:
        """Автофильтр по всей таблице: строка заголовков и все добавленные строки."""
        self.ws.auto_filter.ref = f"A1:{get_column_letter(max(1, ncols))}{max(1, self.rows)}"

    def landscape_fit(self, title_rows: str = "1:1") -> None:
        """Печать: альбомная ориентация, ширина листа по ширине страницы, заголовок на каждой странице."""
        self.ws.page_setup.orientation = "landscape"
        self.ws.page_setup.fitToWidth, self.ws.page_setup.fitToHeight = 1, 0
        self.ws.sheet_properties.pageSetUpPr.fitToPage = True
        self.ws.print_title_rows = title_rows


class Book:
    def __init__(self) -> None:
        self.wb = Workbook(write_only=True)

    def sheet(self, title: str) -> Sheet:
        return Sheet(self.wb.create_sheet(title))

    def save(self, path: Path) -> None:
        self.wb.save(path)
