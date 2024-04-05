#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -eo pipefail

NAME=the-bastion-devenv
BASEDIR=$(readlink -f "$(dirname "$0")/../..")

docker_run() {
    echo "The Bastion devenv docker wasn't running, starting it..."
    docker run -d --name $NAME -v "$BASEDIR:/opt/bastion" $NAME
}

docker_build() {
    echo "The Bastion devenv docker image has never been built, building it..."
    docker build -t $NAME:latest -f "$(dirname "$0")/Dockerfile" "$BASEDIR"
}

is_running=$(docker inspect --type=container --format='{{ .State.Running }}' $NAME 2>/dev/null || true)
case "$is_running" in
    false)
        # not running, but container exists, start it
        docker start $NAME
        ;;
    true)
        # running, nothing to do
        ;;
    *)
        # docker instance doesn't exist, is the image already built?
        if docker image history $NAME >/dev/null 2>&1; then
            # yes: just run it, then
            docker_run
        else
            # no: build it first
            docker_build
            # then run it
            docker_run
        fi
        ;;
esac

cmd="${1:-}"
shift || true

case "$cmd" in
    tidy)       docker exec $NAME /opt/bastion/bin/dev/perl-tidy.sh tidy "$@";;
    checktidy)  docker exec $NAME /opt/bastion/bin/dev/perl-tidy.sh test "$@";;
    perlcritic) docker exec $NAME /opt/bastion/bin/dev/perl-critic.sh;;
    shellcheck) docker exec $NAME /opt/bastion/bin/dev/shell-check.sh system "$@";;
    lint)
        docker exec $NAME /opt/bastion/bin/dev/perl-tidy.sh tidy "$@"
        docker exec $NAME /opt/bastion/bin/dev/perl-critic.sh
        docker exec $NAME /opt/bastion/bin/dev/shell-check.sh system "$@"
        ;;
    rebuild)
        docker rm -f $NAME
        docker image rm $NAME
        docker_build
        docker_run
        echo "The Bastion devenv has been rebuilt successfully."
        ;;
    doc)
        docker exec $NAME bash -c 'cd /opt/bastion/doc/sphinx && make';;
    sphinx-view-objects)
        docker exec $NAME python3 -m sphinx.ext.intersphinx /opt/bastion/doc/sphinx/_build/html/objects.inv;;
    doc-serve)
        if [ -n "$1" ]; then
            pkill -f "python3 -m http.server $1" || true
            ( cd "$BASEDIR/docs" && python3 -m http.server "$1" 2>/dev/null ) &
        else
            echo "Usage: $0 doc-serve PORT"
            exit 1
        fi
        ;;
    bash) docker exec -it $NAME bash;;
    run) docker exec -it $NAME "$@";;
    *)
        cat <<EOF
Usage: $0 COMMAND [OPTIONS]

  COMMAND may be one of the following:

  tidy       [FILES..] runs perltidy on several or all the Perl source files, modifying them if needed
  checktidy  [FILES..] runs perltidy in dry-run mode, and returns an error if files are not tidy
  perlcritic           runs perlcritic on all the Perl source files
  shellcheck [FILES..] runs shellcheck on all the shell source files
  lint                 runs tidy, perlcritic and shellcheck on all files in one command

  doc                  generates the documentation
  sphinx-view-objects  shows the named objects of the Sphinx documentation that can be referenced
  doc-serve <PORT>     starts a local HTTP python server on PORT to view generated documentation

  bash                 spawn an interactive shell to run any arbitrary command in the devenv docker
  run <COMMAND>        run an arbitrary command in the devenv docker
  rebuild              forces the rebuild of the devenv docker image that is needed to run all the above commands

EOF
esac
