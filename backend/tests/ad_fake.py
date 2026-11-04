"""Каталог в памяти для проверки просмотра AD без сервера: разбор подмножества LDAP-фильтров, область поиска, выбор атрибутов. Все данные вымышленные."""
import re
import uuid

from app.ad import filters as F

BASE = "DC=corp,DC=example,DC=local"
DOM_SID = "S-1-5-21-111-222-333"


def _b(v):
    return v if isinstance(v, bytes) else str(v).encode()


def entry(dn, **attrs):
    return {"dn": dn, "attrs": {k: [_b(x) for x in (v if isinstance(v, list) else [v])] for k, v in attrs.items()}}


def parse(s, i=0):
    """(…) → дерево: ('&'|'|', [..]) | ('!', x) | ('eq', attr, value) | ('ext', attr, oid, value)."""
    assert s[i] == "("
    c = s[i + 1]
    if c in "&|":
        i += 2
        kids = []
        while s[i] == "(":
            k, i = parse(s, i)
            kids.append(k)
        return (c, kids), i + 1
    if c == "!":
        k, i = parse(s, i + 2 - 1)
        return ("!", k), i + 1
    j = s.index(")", i)
    # значение может содержать «\29» — экранированная скобка не встречается как «)»
    body = s[i + 1:j]
    m = re.match(r"^([\w;.-]+?)(?::([\d.]+):)?(>=|<=|=)(.*)$", body)
    a, oid, op, val = m.groups()
    return (("ext", a, oid, val) if oid else ("op", a, op, val)), j + 1


def unesc(v):
    return re.sub(r"\\([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), v)


def raw_unesc(v) -> bytes:
    return bytes(int(h, 16) for h in re.findall(r"\\([0-9a-fA-F]{2})", v)) if re.fullmatch(r"(\\[0-9a-fA-F]{2})+", v) else v.encode()


class Dir:
    def __init__(self, entries):
        self.e = {x["dn"].lower(): x for x in entries}

    def vals(self, x, name):
        low = name.lower()
        for k, v in x["attrs"].items():
            if k.lower() == low:
                return v
        return []

    def groups_of(self, dn, seen=None):
        """Эффективные группы: рекурсивно по member."""
        seen = seen if seen is not None else set()
        for g in self.e.values():
            if dn.encode().lower() in [m.lower() for m in self.vals(g, "member")] and g["dn"].lower() not in seen:
                seen.add(g["dn"].lower())
                self.groups_of(g["dn"], seen)
        return seen

    def match(self, x, node):
        t = node[0]
        if t == "&":
            return all(self.match(x, k) for k in node[1])
        if t == "|":
            return any(self.match(x, k) for k in node[1])
        if t == "!":
            return not self.match(x, node[1])
        if t == "ext":
            _t, attr, oid, val = node
            if oid.endswith(".803"):                                  # побитовое И (LDAP_MATCHING_RULE_BIT_AND)
                return any(int(h) & int(val) == int(val) for h in self.vals(x, attr))
            return self._chain(x, attr, unesc(val))
        _t, attr, op, val = node
        if attr.lower() == "distinguishedname":
            return x["dn"].lower() == unesc(val).lower()
        have = self.vals(x, attr)
        if val == "*":
            return bool(have)
        if op in (">=", "<="):
            try:
                return any((int(h) >= int(val)) if op == ">=" else (int(h) <= int(val)) for h in have)
            except ValueError:
                return False
        if attr.lower() in ("objectguid", "objectsid", "tokengroups"):
            return raw_unesc(val) in have
        pat = re.compile("^" + ".*".join(re.escape(unesc(p)) for p in val.split("*")) + "$", re.I | re.S)
        return any(pat.match(h.decode("utf-8", "ignore")) for h in have)

    def _chain(self, x, attr, dn):
        if attr.lower() == "memberof":
            return dn.lower() in self.groups_of(x["dn"])
        if attr.lower() == "member":                                  # группы, в которые (в том числе косвенно) входит dn
            return x["dn"].lower() in self.groups_of(dn)
        return False

    def search(self, base, flt, attrs, scope="SUBTREE", max_n=500):
        tree, _ = parse(flt)
        out = []
        for x in self.e.values():
            dn = x["dn"].lower()
            if scope == "BASE":
                if dn != base.lower():
                    continue
            elif not (dn == base.lower() or dn.endswith("," + base.lower())):
                continue
            if self.match(x, tree):
                out.append(self.render(x, attrs))
        return out[:max_n], len(out) > max_n

    def render(self, x, attrs):
        want = {a.lower() for a in attrs}
        raw = {k: v for k, v in x["attrs"].items() if "*" in want or k.lower() in want}
        if "tokengroups" in want:
            raw["tokenGroups"] = [F.sid_bytes(sid) for sid in self.token_groups(x)]
        return {"type": "searchResEntry", "dn": x["dn"], "raw_attributes": raw, "attributes": {}}

    def token_groups(self, x):
        out = []
        for gdn in self.groups_of(x["dn"]) | ({self.primary(x)} if self.primary(x) else set()):
            g = self.e[gdn]
            out.append(F.sid_str(self.vals(g, "objectSid")[0]))
        return out

    def primary(self, x):
        rid = self.vals(x, "primaryGroupID")
        if not rid:
            return None
        sid = f"{DOM_SID}-{rid[0].decode()}"
        for g in self.e.values():
            if self.vals(g, "objectSid") and F.sid_str(self.vals(g, "objectSid")[0]) == sid:
                return g["dn"].lower()
        return None


def user(cn, sam, mail, dept="", title="", uac=512, member_of=(), primary=513, **extra):
    guid = uuid.uuid5(uuid.NAMESPACE_DNS, sam)
    rid = 1000 + len(sam) * 7 + sum(map(ord, sam)) % 500
    a = dict(cn=cn, displayName=cn, sAMAccountName=sam, userPrincipalName=f"{sam}@corp.example.local", mail=mail, department=dept, title=title, userAccountControl=str(uac), objectClass=["top", "person", "user"], objectCategory="person",
             objectGUID=guid.bytes_le, objectSid=F.sid_bytes(f"{DOM_SID}-{rid}"), primaryGroupID=str(primary), whenCreated="20240301080000.0Z", whenChanged="20241002101500.0Z", pwdLastSet="133700000000000000",
             accountExpires="9223372036854775807", userPassword="SECRET", unicodePwd=b"\x00\x01", memberOf=list(member_of), company="ООО Пример")
    a.update(extra)
    return entry(f"CN={cn},OU=Users,{BASE}", **{k: v for k, v in a.items() if v != ""})


def group(cn, sid_rid, members=(), gtype=-2147483646, desc=""):
    return entry(f"CN={cn},OU=Groups,{BASE}", cn=cn, sAMAccountName=cn, description=desc, groupType=str(gtype), objectClass=["top", "group"], objectGUID=uuid.uuid5(uuid.NAMESPACE_DNS, "g" + cn).bytes_le,
                 objectSid=F.sid_bytes(f"{DOM_SID}-{sid_rid}"), member=list(members))
