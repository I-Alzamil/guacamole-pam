/**
 * The "PAM Settings" tab: the settings shared by every Guacamole server
 * using the database, editable, and below them this server's own, read
 * only, as its guacamole.properties sets them.
 */
angular.module('guacPam').directive('guacSettingsPamSettings', [function guacSettingsPamSettings() {

    return {
        restrict    : 'E',
        replace     : true,
        scope       : {},
        templateUrl : 'app/ext/pam/templates/settingsPamSettings.html',
        controller  : ['$scope', '$injector', function settingsPamSettingsController($scope, $injector) {

            // Required services
            var guacNotification = $injector.get('guacNotification');
            var pamService       = $injector.get('pamService');

            /**
             * The shared settings as stored, or null while loading.
             */
            $scope.entries = null;

            /**
             * This server's own settings, or null while loading.
             */
            $scope.server = null;

            /**
             * The values being edited, by setting name.
             */
            $scope.values = {};

            /**
             * Whether a save is under way.
             */
            $scope.saving = false;

            var show = function show(settings) {
                $scope.entries = settings.settings;
                $scope.server = settings.server;
                $scope.values = {};
                angular.forEach($scope.entries, function copyValue(entry) {
                    $scope.values[entry.name] = entry.value;
                });
            };

            pamService.getSettings().then(show, guacNotification.SHOW_REQUEST_ERROR);

            /**
             * The translation key part naming a setting:
             * "pam-max-extensions" is "MAX_EXTENSIONS".
             */
            $scope.key = function key(entry) {
                return entry.name.replace(/^pam-/, '').replace(/-/g, '_').toUpperCase();
            };

            /**
             * A value as shown: "Yes" or "No" for a yes/no, else as is.
             */
            $scope.label = function label(entry, value) {
                if (entry.type === 'BOOLEAN')
                    return value ? 'PAM_SETTINGS.INFO_YES' : 'PAM_SETTINGS.INFO_NO';
                return String(value);
            };

            var changes = function changes() {
                var changed = {};
                angular.forEach($scope.entries, function compare(entry) {
                    if ($scope.values[entry.name] !== entry.value)
                        changed[entry.name] = $scope.values[entry.name];
                });
                return changed;
            };

            $scope.isDirty = function isDirty() {
                return !angular.equals(changes(), {});
            };

            /**
             * Whether any setting has a value set, rather than its default.
             */
            $scope.anySet = function anySet() {
                return ($scope.entries || []).some(function isSet(entry) { return entry.set; });
            };

            var save = function save(values) {
                $scope.saving = true;
                pamService.updateSettings(values).then(function saved(settings) {
                    show(settings);
                    guacNotification.showStatus({
                        title   : 'PAM.TAB_SETTINGS',
                        text    : { key : 'PAM.INFO_SAVED' },
                        actions : [{
                            name     : 'PAM.ACTION_CLOSE',
                            callback : function closeStatus() { guacNotification.showStatus(false); }
                        }]
                    });
                }, guacNotification.SHOW_REQUEST_ERROR)['finally'](function saveEnded() {
                    $scope.saving = false;
                });
            };

            $scope.save = function saveChanges() {
                save(changes());
            };

            /**
             * Sets every setting back to its default, discarding edits.
             */
            $scope.restoreDefaults = function restoreDefaults() {
                var defaults = {};
                angular.forEach($scope.entries, function reset(entry) {
                    if (entry.set)
                        defaults[entry.name] = null;
                });
                save(defaults);
            };

        }]
    };

}]);
