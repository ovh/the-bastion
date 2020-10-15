CONFIGFILE=/etc/bastion/luks-config.sh
if [ -r $CONFIGFILE ] ; then
    . $CONFIGFILE
    if [ -n "$MOUNTPOINT" ] ; then
        export PROMPT_COMMAND="test -e $MOUNTPOINT/allowkeeper && LUKSINFO= || LUKSINFO='<<LOCKED>>'"
        PS1='$LUKSINFO'"$PS1"
    fi
fi


