#! /usr/bin/env bash
set -u
cd $(dirname $0)/../.. || exit 1

print_title() {
    title="$1"
    titlelength=$(echo "$title" | wc -c)
    for i in $(seq 1 $titlelength)
    do
        echo -n '='
    done
    echo
    echo "$title"
    for i in $(seq 1 $titlelength)
    do
        echo -n '='
    done
    echo
    echo
    unset titlelength
    unset title
}

rm -rf doc/sphinx/plugins
mkdir doc/sphinx/plugins

export PLUGIN_QUIET=1
export PLUGIN_HELP=1
export PLUGIN_DOCGEN=1
export ANSI_COLORS_DISABLED=1

for pluginfile in $(find bin/plugin -executable -type f -print)
do
    pluginname=$(echo "$pluginfile" | cut -d/ -f3-)
    docfile="doc/sphinx/plugins/$pluginname.rst"
    docdir=$(dirname "$docfile")
    name=$(basename "$pluginname")
    [ -d "$docdir" ] || mkdir -p "$docdir"
    echo "$docfile..."
    {
        print_title "$name"
        if [ -e "doc/sphinx-plugins-override/$name.override.rst" ]; then
            cat "doc/sphinx-plugins-override/$name.override.rst"
        else
            perl "$pluginfile" '' '' '' '' | perl -ne '
                if (m{^Usage: (.+)}) { print ".. admonition:: usage\n   :class: cmdusage\n\n   $1\n\n.. program:: '"$name"'\n\n"; }
                elsif (m{^  (-[- ,a-z|/A-Z"'"'"']+)  (.+)}) { print ".. option:: $1\n\n   $2\n\n"; }
                elsif ($l++ == 0) { chomp; print "$_\n"."="x(length($_))."\n\n"; }
                else { print "$_"; }
            '
            pluginret=${PIPESTATUS[0]}
            if [ "$pluginret" != 100 ] && [ "$pluginret" != 0 ]; then
                echo "Unexpected return code from the plugin ($pluginret), aborting!" >&2
                exit 1
            fi
            if [ -e "doc/sphinx-plugins-override/$name.rst" ]; then
                echo "... adding doc/sphinx-plugins-override/$name.rst" >&2
                #printf "\n.. highlight:: shell\n\n"
                cat "doc/sphinx-plugins-override/$name.rst"
            fi
        fi
    } > "$docfile"
done

pluginindex="doc/sphinx/plugins/index.rst"
print_title "Bastion plugins" > "$pluginindex"
cat >>"$pluginindex" <<EOF
.. toctree::

EOF

for section in $(find doc/sphinx/plugins -mindepth 1 -maxdepth 1 -type d | LC_ALL=C sort)
do
    indexfile="$section/index.rst"
    section=$(basename "$section")
    echo "Working on $section"
    echo "   $section/index.rst" >> "$pluginindex"
    print_title "$section plugins" > "$indexfile"
    cat >>"$indexfile" <<EOF
.. toctree::

EOF
    for plugin in $(find doc/sphinx/plugins/$section -type f -name "*.rst" ! -name "index.rst" | LC_ALL=C sort)
    do
        echo "   $(basename $plugin .rst)" >> "$indexfile"
    done
done
