"""Pretvara CSV izvoz iz stare Google tabele u SQL za uvoz u Supabase.

Upotreba:
  python3 csv_to_sql.py Drivers.csv Sheet1.csv > import.sql
Zatim: Supabase → SQL Editor → nalepi import.sql → Run.

Drivers.csv:  Full Name, Driver ID            (red 1 = zaglavlje)
Sheet1.csv:   Date (ili Date & Time), Full Name, Driver ID, Truck Number, Trailer Number,
              Truck Photos, Trailer Photos, Driver Notes, Admin Comment
"""
import csv, re, sys
from datetime import datetime


def lit(s):
    """SQL tekst literal (bez ikakvog tumačenja sadržaja)."""
    return "'" + str(s).replace("'", "''") + "'"


def arr(cell):
    urls = [u.strip() for u in (cell or '').split('|') if u.strip().startswith('https://')]
    return 'ARRAY[' + ','.join(lit(u) for u in urls) + ']::text[]' if urls else "'{}'::text[]"


def parse_date(s):
    s = (s or '').strip()
    first = s.split(',')[0].strip()           # "10/5/2026, 3:41:00 PM" → "10/5/2026"
    for fmt in ('%m/%d/%Y', '%Y-%m-%d', '%d.%m.%Y', '%m/%d/%y'):
        try:
            return datetime.strptime(first, fmt).date().isoformat()
        except ValueError:
            pass
    return None


def rows(path):
    with open(path, newline='', encoding='utf-8-sig') as f:
        data = list(csv.reader(f))
    return data[1:] if data else []


def main(drivers_csv, reports_csv=None):
    out = ['-- Uvoz iz Google tabele', 'begin;']
    warn = []

    seen = set()
    n_drv = 0
    for i, r in enumerate(rows(drivers_csv), start=2):
        name = re.sub(r'\s+', ' ', (r[0] if len(r) > 0 else '')).strip()
        did = (r[1] if len(r) > 1 else '').strip()
        if not name and not did:
            continue
        if len(name) < 2 or not re.fullmatch(r'\d{4}', did):
            warn.append(f'Drivers red {i}: preskočen ({name!r}, {did!r}) – ime ili ID nije ispravan')
            continue
        key = (name.lower(), did)
        if key in seen:
            warn.append(f'Drivers red {i}: duplikat {name} {did} – preskočen')
            continue
        seen.add(key)
        out.append(f'insert into public.drivers (full_name, driver_id) values ({lit(name)}, {lit(did)});')
        n_drv += 1

    n_rep = 0
    if reports_csv:
        for i, r in enumerate(rows(reports_csv), start=2):
            r = (r + [''] * 9)[:9]
            date, name, did, truck, trailer, tp, trp, notes, comment = [c.strip() for c in r]
            if not any(r):
                continue
            d = parse_date(date)
            if not d:
                warn.append(f'Sheet1 red {i}: nepoznat datum {date!r} – preskočen')
                continue
            out.append(
                'insert into public.reports (report_date, driver_name, driver_id, truck, trailer, '
                'truck_photos, trailer_photos, notes, admin_comment) values ('
                f'{lit(d)}, {lit(name)}, {lit(did)}, {lit(truck)}, {lit(trailer)}, '
                f'{arr(tp)}, {arr(trp)}, {lit(notes)}, {lit(comment)});')
            n_rep += 1

    out.append('commit;')
    out.append(f'-- vozača: {n_drv}, izveštaja: {n_rep}')
    print('\n'.join(out))
    for w in warn:
        print('UPOZORENJE:', w, file=sys.stderr)
    print(f'Gotovo: {n_drv} vozača, {n_rep} izveštaja, {len(warn)} upozorenja.', file=sys.stderr)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
