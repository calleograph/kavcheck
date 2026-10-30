"""Вымышленная выгрузка адресной книги для проверки раздела «Иерархия. Предприятие»: 352 записи → 279 после очистки (22 внешних, 40 пустых, 8 с «_», 3 служебных).
Есть самоссылка (верхний руководитель), круг, руководитель только текстом (не найден, неоднозначный и единственный по ФИО), руководитель вне выгрузки, синонимы подразделений и пустые подразделения."""
import random

DOMAIN = "demo-company.example"
DEPTS = ["Департамент продаж", "Департамент разработки", "Департамент поддержки", "Отдел информационных технологий", "Отдел персонала", "Финансовый отдел", "Юридический отдел"]
FAM = ["Орлов", "Лебедев", "Ершов", "Тихонов", "Галкин", "Фролов", "Савин", "Зимин", "Нестеров", "Хохлов", "Ильин", "Жуков", "Беляев", "Мельников"]
NAM = ["Олег Олегович", "Игорь Игоревич", "Роман Романович", "Денис Денисович", "Павел Павлович", "Кирилл Кириллович", "Борис Борисович", "Тимур Тимурович"]


def rec(name, email, title="", dept="", mgr="", mgr_email="", company="", office=""):
    return {"Name": name, "Email": email, "JobTitle": title, "Department": dept, "Company": company, "Office": office, "Manager": mgr, "ManagerEmail": mgr_email}


def demo_records() -> list[dict]:
    out, n = [], [0]

    def user(name, title, dept, boss=None, **kw):
        n[0] += 1
        e = f"user{n[0]:04d}@{DOMAIN}"
        out.append(rec(name, e, title, dept, boss[0] if boss else kw.pop("mgr", ""), boss[1] if boss else kw.pop("mgr_email", ""), **kw))
        return name, e

    ceo = user("Ершов Павел Павлович", "Генеральный директор", "Руководство компании")
    out[-1]["Manager"], out[-1]["ManagerEmail"] = ceo[0], ceo[1]                              # самоссылка: верхний уровень
    dirs = [user(f"Директор{i} Иван Иванович", f"Директор по направлению {i}", DEPTS[i], ceo) for i in range(7)]
    heads = []
    for i in range(21):
        heads.append(user(f"Руководов{i:02d} Пётр Петрович", f"Руководитель группы {i}", DEPTS[i % 7] if i % 4 else "ИТ" if i % 7 == 3 else "", dirs[i % 7]))
    special = 0
    cyc_a = user("Кругов Алексей Алексеевич", "Специалист", DEPTS[4], mgr="Кругова Анна Андреевна", mgr_email=f"user{n[0] + 2:04d}@{DOMAIN}")
    cyc_b = user("Кругова Анна Андреевна", "Специалист", DEPTS[4], mgr="Кругов Алексей Алексеевич", mgr_email=cyc_a[1])
    user("Подкруговов Сергей Сергеевич", "Инженер", "", cyc_a)                                # подчинённый человека из круга
    for i in range(3):
        user(f"Безадресов{i} Олег Олегович", "Консультант", DEPTS[2], mgr="Руководитель без адреса")
    user("Поискови Тимур Тимурович", "Аналитик", DEPTS[5], mgr=heads[0][0])                   # руководитель только текстом, единственное совпадение по ФИО
    user("Двойнов Борис Борисович", "Аналитик", DEPTS[5], mgr="Тёзкин Игорь Игоревич")        # два человека с таким ФИО → неоднозначно
    user("Тёзкин Игорь Игоревич", "Менеджер", DEPTS[1], dirs[1])
    user("Тёзкин Игорь Игоревич", "Менеджер", DEPTS[2], dirs[2])
    out.append(rec("Тёзкин Игорь Игоревич", f"user9999@{DOMAIN}", "Старший менеджер", DEPTS[2], "", "", ))                         # третий — не нужен: оставляем два совпадения ниже
    out.pop()
    user("Внешнеруков Фёдор Фёдорович", "Менеджер", DEPTS[0], mgr="Внешний Контакт 3", mgr_email="ext3@partner1.example")             # руководитель вне выгрузки
    for i in range(8):
        user(f"Безруков{i} Роман Романович", "Консультант", DEPTS[4], mgr="", mgr_email="")                                           # руководитель не указан
    base = len(out)
    i = 0
    rnd = random.Random(5)
    while sum(1 for r in out if r["Email"].endswith(DOMAIN) and r["Email"].startswith("user")) < 279:
        boss = rnd.choice(heads + dirs)
        d = rnd.choice(DEPTS + ["", "", "ИТ"])
        user(f"{FAM[i % len(FAM)]}{i // len(FAM) or ''} {NAM[i % len(NAM)]}", rnd.choice(["Инженер", "Аналитик", "Специалист", "Менеджер", "Консультант"]), d, boss)
        i += 1
    _ = base, special
    for i in range(40):
        out.append(rec(f"ящик{i}", f"box{i}@{DOMAIN}"))                                                                             # пустые карточки
    for i in range(8):
        out.append(rec(f"_Рассылка {i}", f"dl{i}@{DOMAIN}", "", DEPTS[4]))
    for i in range(3):
        out.append(rec(f"Служебная {i}", f"service{i}@{DOMAIN}", "служебная учетная запись"))
    for i in range(22):
        out.append(rec(f"Внешний Контакт {i}", f"ext{i}@partner{i % 4}.example", "Менеджер"))
    random.Random(11).shuffle(out)
    return out
