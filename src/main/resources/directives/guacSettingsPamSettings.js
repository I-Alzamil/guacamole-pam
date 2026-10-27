/**
 * The "PAM Settings" tab: the settings shared by every Guacamole server
 * using the database, in sections: general settings, then each output of
 * events, which can be tested once saved.
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
             * Sections whose settings can be tested, by name.
             */
            var TESTABLE = { SYSLOG : true, EMAIL : true };

            /**
             * The shared settings as stored, or null while loading.
             */
            $scope.entries = null;

            /**
             * The settings by section, in the order received: each with its
             * "name" ("GENERAL") and "entries".
             */
            $scope.sections = [];

            /**
             * The values being edited, by setting name. A secret's is what
             * was typed: empty keeps the one set.
             */
            $scope.values = {};

            /**
             * The secrets to remove, by setting name.
             */
            $scope.removed = {};

            /**
             * Whether a save is under way.
             */
            $scope.saving = false;

            /**
             * Whether a test is under way.
             */
            $scope.testing = false;

            var show = function show(settings) {
                $scope.entries = settings;
                $scope.values = {};
                $scope.removed = {};
                $scope.sections = [];
                var byName = {};
                angular.forEach($scope.entries, function copyValue(entry) {
                    $scope.values[entry.name] = entry.type === 'SECRET' ? '' : entry.value;
                    if (!byName[entry.section]) {
                        byName[entry.section] = { name : entry.section, entries : [] };
                        $scope.sections.push(byName[entry.section]);
                    }
                    byName[entry.section].entries.push(entry);
                });
            };

            pamService.getSettings().then(show, guacNotification.SHOW_REQUEST_ERROR);

            /**
             * Why this server is on standby, read-only for PAM, such as
             * "OTHER_SERVER", to say so; null if PAM works on it.
             */
            $scope.standby = null;

            /**
             * The names of the languages emails are written in, by code.
             */
            $scope.languages = {};

            pamService.getServer().then(function serverRead(server) {
                $scope.standby = server.standby;
                $scope.languages = server.emailLanguages || {};
            }, angular.noop);


            /**
             * The translation key part naming a setting:
             * "pam-max-extensions" is "MAX_EXTENSIONS".
             */
            $scope.key = function key(entry) {
                return entry.name.replace(/^pam-/, '').replace(/-/g, '_').toUpperCase();
            };

            /**
             * The translation key of an option of a choice.
             */
            $scope.optionLabel = function optionLabel(entry, option) {
                return 'PAM_SETTINGS.OPTION_' + $scope.key(entry) + '_' + option.replace(/-/g, '_').toUpperCase();
            };

            /**
             * A value as shown: "Yes" or "No" for a yes/no, an option's
             * label, "None" for no text, a language's name, else as is.
             */
            $scope.label = function label(entry, value) {
                if (entry.type === 'BOOLEAN')
                    return value ? 'PAM_SETTINGS.INFO_YES' : 'PAM_SETTINGS.INFO_NO';
                if (entry.type === 'ENUM')
                    return $scope.optionLabel(entry, value);
                if (entry.name === 'pam-email-language')
                    return $scope.languages[value] || value;
                if (value === null || value === undefined || value === '')
                    return 'PAM_SETTINGS.INFO_NONE';
                return String(value);
            };

            /**
             * A text value as sent: none rather than empty.
             */
            var normalized = function normalized(entry, value) {
                if ((entry.type === 'STRING' || entry.type === 'TEXT') && (value === undefined || value === ''))
                    return null;
                return value;
            };

            var changes = function changes() {
                var changed = {};
                angular.forEach($scope.entries, function compare(entry) {
                    if (entry.type === 'SECRET') {
                        if ($scope.removed[entry.name])
                            changed[entry.name] = null;
                        else if ($scope.values[entry.name])
                            changed[entry.name] = $scope.values[entry.name];
                    }
                    else if (normalized(entry, $scope.values[entry.name]) !== normalized(entry, entry.value))
                        changed[entry.name] = normalized(entry, $scope.values[entry.name]);
                });
                return changed;
            };

            $scope.isDirty = function isDirty() {
                return !angular.equals(changes(), {});
            };

            /**
             * Whether any setting of the section has a value set, rather
             * than its default.
             */
            $scope.anySet = function anySet(section) {
                return section.entries.some(function isSet(entry) { return entry.set; });
            };

            $scope.isTestable = function isTestable(section) {
                return !!TESTABLE[section.name];
            };

            var closeStatus = {
                name     : 'PAM.ACTION_CLOSE',
                callback : function closeStatus() { guacNotification.showStatus(false); }
            };

            var save = function save(values) {
                $scope.saving = true;
                pamService.updateSettings(values).then(function saved(settings) {
                    show(settings);
                    guacNotification.showStatus({
                        title   : 'PAM.TAB_SETTINGS',
                        text    : { key : 'PAM.INFO_SAVED' },
                        actions : [ closeStatus ]
                    });
                }, guacNotification.SHOW_REQUEST_ERROR)['finally'](function saveEnded() {
                    $scope.saving = false;
                });
            };

            $scope.save = function saveChanges() {
                save(changes());
            };

            /**
             * Sets every setting of the section back to its default,
             * discarding edits.
             */
            $scope.restoreDefaults = function restoreDefaults(section) {
                var defaults = {};
                angular.forEach(section.entries, function reset(entry) {
                    if (entry.set)
                        defaults[entry.name] = null;
                });
                save(defaults);
            };

            /**
             * Sends a test through the section's output, as saved, saying
             * what came of it.
             */
            $scope.test = function test(section) {
                $scope.testing = true;
                pamService.testSettings(section.name.toLowerCase()).then(function tested(result) {
                    guacNotification.showStatus({
                        title   : 'PAM_SETTINGS.SECTION_HEADER_' + section.name,
                        className : result.sent ? '' : 'error',
                        text    : { key : result.sent ? 'PAM_SETTINGS.INFO_TEST_SENT' : 'PAM_SETTINGS.INFO_TEST_FAILED',
                                    variables : { MESSAGE : result.message } },
                        actions : [ closeStatus ]
                    });
                }, guacNotification.SHOW_REQUEST_ERROR)['finally'](function testEnded() {
                    $scope.testing = false;
                });
            };

        }]
    };

}]);
