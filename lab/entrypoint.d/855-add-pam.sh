#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

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
