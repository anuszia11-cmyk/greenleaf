# IDOR Vulnerability Report – `/borrower/<id>`



| Field | Value |
|---|---|
| Project | GreenLeaf Microfinance – Secure Lending Portal |
| Tester | Anas Zia |
| Date tested | 2026-11-25 |
| Affected endpoint | `GET /borrower/<id>` |
| Vulnerability | Insecure Direct Object Reference (IDOR) |
| Category | OWASP Top 10 2021 – **A01: Broken Access Control**; CWE-639 (Authorization Bypass Through User-Controlled Key) |
| CVSS 3.1 (estimate) | 6.5 Medium – `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| Business risk | **High** – every borrower's national ID and loan balance can be read |
| Status | **Fixed** and covered by automated tests |

---

## 1. Summary

The borrower detail page loads a record using the numeric ID taken straight from the URL. The application checked that the user was **logged in** (authentication), but never checked that the record **belongs to** that user (authorization). Any logged-in borrower could change the number in the URL and read any other borrower's private data.

## 2. Steps to reproduce (before the fix)

1. Start the app: `flask run`
2. Log in as `borrower1` (password `GreenLeaf@123`).
3. Open `http://127.0.0.1:5000/borrower/1` – your own record loads (expected).
4. Change the URL to `http://127.0.0.1:5000/borrower/2`.
5. Borrower 2's name, national ID and loan balance are displayed. **No error is shown.**

The same attack with curl:

```bash
# log in and save the session cookie
curl -c cookies.txt -d "username=borrower1&password=GreenLeaf@123" http://127.0.0.1:5000/login

# request someone else's record with borrower1's cookie
curl -i -b cookies.txt http://127.0.0.1:5000/borrower/2
```

## 3. Evidence (before the fix)

<!-- REPLACE with your own output + screenshot -->

**Request**

```http
GET /borrower/2 HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=<borrower1 session cookie>
```

**Response – HTTP 200, borrower 2's data leaked**

```html
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<h2>Borrower #2</h2>
<table>
  <tr><th>Name</th><td>Bilal Ahmed</td></tr>
  <tr><th>National ID</th><td>35202-2222222-2</td></tr>
  <tr><th>Loan balance</th><td>PKR 48,000.00</td></tr>
</table>
```

Screenshot: `screenshots/idor_before_fix.png`

**Enumeration** – a simple loop dumped all 10 borrowers while logged in as borrower 1:

```bash
for i in $(seq 1 10); do curl -s -b cookies.txt http://127.0.0.1:5000/borrower/$i | grep "National ID"; done
```

```text
/borrower/1   -> Ayesha Khan 35202-1111111-1
/borrower/2   -> Bilal Ahmed 35202-2222222-2
...
/borrower/10  -> Hamza Shah 35202-1010101-0
```

## 4. Impact

- **Confidentiality breach:** full name, national ID number and loan balance of every borrower are exposed to any registered user.
- **Easy mass extraction:** IDs are sequential (1, 2, 3 …), so the whole table can be downloaded with a 1-line script; no special tools or skills needed.
- **Identity fraud risk:** national ID numbers combined with names can be used to impersonate borrowers or open fraudulent loans.
- **Legal and trust damage:** leaking customers' financial and identity data breaks data-protection obligations and destroys the trust a microfinance cooperative depends on.

## 5. Root cause

```python
@app.route("/borrower/<int:borrower_id>")
@login_required                       # checks: is the user logged in?   ✔
def borrower_detail(borrower_id):     # never checks: is this THEIR record? ✘
    borrower = db.execute("SELECT * FROM borrowers WHERE id = ?", (borrower_id,)).fetchone()
```

The server trusted a value the user controls (the URL) to decide whose data to return.

## 6. Fix

The server now compares the borrower ID stored in the **session** (set by the server at login and signed with `SECRET_KEY`, so the user cannot edit it) with the ID requested in the URL. If they differ, the request is stopped with **403 Forbidden** before the database is queried, and the attempt is logged.

```python
@app.route("/borrower/<int:borrower_id>")
@login_required
def borrower_detail(borrower_id):
    if session.get("borrower_id") != borrower_id:
        app.logger.warning(
            "IDOR blocked: user=%s (borrower %s) tried to open borrower %s",
            session.get("username"), session.get("borrower_id"), borrower_id,
        )
        abort(403)
    ...
```

Supporting changes:

- Custom `403.html` page via `@app.errorhandler(403)` – shows a clear message and leaks no data.
- Dashboard now lists only the logged-in borrower's own record instead of every borrower.

## 7. Verification (after the fix)

<!-- REPLACE with your own output + screenshot -->

```text
GET /borrower/1  (as borrower1)  ->  HTTP 200 OK        (own record still works)
GET /borrower/2  (as borrower1)  ->  HTTP 403 FORBIDDEN (blocked)
```

Server log: `WARNING in app: IDOR blocked: user=borrower1 (borrower 1) tried to open borrower 2`

Screenshot: `screenshots/idor_after_fix_403.png`

**Automated tests** (`tests/test_idor.py`):

```text
tests/test_idor.py::test_borrower_can_view_own_record        PASSED
tests/test_idor.py::test_borrower1_gets_403_for_borrower2     PASSED
tests/test_idor.py::test_no_record_except_own_is_reachable    PASSED
tests/test_idor.py::test_logged_out_user_is_sent_to_login     PASSED
4 passed
```

Against the old vulnerable code the same suite fails (`assert 200 == 403`), proving the tests really detect the bug.

## 8. Further recommendations

1. **Check ownership on every endpoint** that takes an ID (future edit, delete, repayment, download routes), not only this page.
2. **Admin access:** if staff need to see all borrowers, add a `role` column and allow `role == "admin"` explicitly; never remove the check.
3. **Random IDs (UUIDs)** make guessing harder but are *not* a fix on their own; the ownership check must stay.
4. **Keep `SECRET_KEY` secret and strong** (environment variable, never in Git). If it leaks, attackers could forge session cookies and bypass this check.
5. **Monitor the `IDOR blocked` log line** – it will feed the detection script and alert dashboard in Task 5.
