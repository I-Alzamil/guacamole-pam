##
## @fn 855-add-pam.sh
##
## Add the PAM extension to the container before starting
##

# Link the PAM extension
# (mounted under a name without its version by lab.sh)
ln -s "/opt/guacamole/extensions/guacamole-pam.jar" "$GUACAMOLE_HOME/extensions/guacamole-pam.jar"

# Every JDBC driver the image has, for Database platforms: Guacamole itself
# only gets the one of its own database
for driver in /opt/guacamole/drivers/*.jar; do
    [ -e "$GUACAMOLE_HOME/lib/$(basename "$driver")" ] || ln -s "$driver" "$GUACAMOLE_HOME/lib/"
done
