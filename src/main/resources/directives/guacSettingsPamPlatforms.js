/**
 * The "Platforms" settings tab: how managed connections are managed (the
 * management type and its settings) and their default rotation policy.
 */
angular.module('guacPam').directive('guacSettingsPamPlatforms', [function guacSettingsPamPlatforms() {

    return {
        restrict    : 'E',
        replace     : true,
        scope       : {},
        templateUrl : 'app/ext/pam/templates/settingsPamPlatforms.html',
        controller  : ['$scope', '$injector', function settingsPamPlatformsController($scope, $injector) {

            // Required services
            var $translate       = $injector.get('$translate');
            var $timeout         = $injector.get('$timeout');
            var $window          = $injector.get('$window');
            var guacNotification = $injector.get('guacNotification');
            var pamFilterText    = $injector.get('pamFilterText');
            var pamService       = $injector.get('pamService');

            /**
             * Settings of new platforms, by type.
             */
            var NEW_PLATFORM_SETTINGS = {
                ssh : {
                    script : '# Each line is sent to the target, followed by Enter.\n'
                           + '# @expect waits until the output contains the given text;\n'
                           + '# @case waits for any of its cases, and runs the lines of\n'
                           + '# the one seen (passwd asks root for no current password).\n'
                           + 'passwd\n'
                           + '@case (?i)\\b(current|old|existing)\\b[^:\\n]*password:\n'
                           + '<OLDPASS>\n'
                           + '@expect assword:\n'
                           + '@case (?i)\\bnew\\b[^:\\n]*password:\n'
                           + '@end\n'
                           + '<NEWPASS>\n'
                           + '@expect assword:\n'
                           + '<NEWPASS>\n'
                }
            };

            /**
             * What a secret field holds while its stored value is kept, as
             * the connection editor shows a stored password (MASK of
             * ConnectionSecrets.java): masked, it looks set, and is left
             * out when sending, which keeps the stored value.
             */
            var STORED_SECRET = '********';

            /**
             * Form of the rotation policy of a platform. Its values are the
             * policy keys of the server.
             */
            $scope.policyForms = [{
                name   : 'policy',
                fields : [
                    { name : 'rotation-mode', type : 'ENUM', options : ['never', 'after-use', 'periodic'] },
                    { name : 'rotation-interval', type : 'NUMERIC' },
                    { name : 'password-length', type : 'NUMERIC' }
                ]
            }];

            /**
             * Management types with the forms of their settings.
             */
            $scope.platformTypes = [];

            /**
             * All platforms, or null while loading.
             */
            $scope.platforms = null;

            /**
             * Copy of the platform being edited, or null.
             */
            $scope.editing = null;

            /**
             * The editing platform as last saved, to detect unsaved changes.
             */
            var original = null;

            /**
             * Whether the editing platform was just saved.
             */
            $scope.saved = false;

            $scope.getType = function getType(name) {
                for (var i = 0; i < $scope.platformTypes.length; i++) {
                    if ($scope.platformTypes[i].name === name)
                        return $scope.platformTypes[i];
                }
                return null;
            };

            /**
             * Usage of each platform for the overview, by identifier, as
             * {connections, failing}.
             */
            $scope.usage = {};

            var loadUsage = function loadUsage() {
                pamService.getConnections().then(function connectionsRetrieved(connections) {
                    var usage = {};
                    angular.forEach(connections, function countConnection(connection) {
                        var entry = usage[connection.platformId] = usage[connection.platformId]
                                || { connections : 0, failing : 0 };
                        entry.connections++;
                        if (connection.status === 'FAILED' || connection.status === 'UNKNOWN')
                            entry.failing++;
                    });
                    $scope.usage = usage;
                }, angular.noop);
            };

            $scope.getUsage = function getUsage(platform) {
                return $scope.usage[String(platform.id)] || { connections : 0, failing : 0 };
            };

            /**
             * Translation key describing the rotation policy of a platform,
             * for the overview.
             */
            $scope.policyKey = function policyKey(platform) {
                var mode = (platform.policy && platform.policy['rotation-mode']) || 'never';
                return 'PAM.INFO_POLICY_' + mode.toUpperCase().replace(/[^A-Z0-9]+/g, '_');
            };

            /**
             * The platforms matching the filter.
             */
            $scope.filteredPlatforms = [];

            /**
             * What the filter matches: the platform's name, description,
             * type and policy, as shown.
             */
            $scope.filteredPlatformProperties = ['pamFilterText'];

            var loadPlatforms = function loadPlatforms() {
                return pamService.getPlatforms().then(function platformsRetrieved(platforms) {
                    angular.forEach(platforms, function addFilterText(platform) {
                        pamFilterText(platform, [
                            platform.name,
                            platform.description,
                            $translate.instant('PAM.TYPE_' + String(platform.type).toUpperCase()),
                            $translate.instant($scope.policyKey(platform),
                                { HOURS : (platform.policy && platform.policy['rotation-interval']) || '?' })
                        ]);
                    });
                    $scope.platforms = platforms;
                }, guacNotification.SHOW_REQUEST_ERROR);
            };

            /**
             * The parts of a platform an administrator edits.
             */
            var editableFields = function editableFields(platform) {
                return platform && {
                    name        : platform.name || '',
                    description : platform.description || '',
                    settings    : normalize(platform.settings),
                    policy      : normalize(platform.policy)
                };
            };

            /**
             * Values as the server stores them, so that what the form fields
             * write back unchanged compares equal: as strings (numeric
             * fields turn 24 into "24"), and without empty values (fields
             * left alone may set "" or null where nothing was set).
             */
            var normalize = function normalize(values) {
                var normalized = {};
                angular.forEach(values || {}, function addValue(value, key) {
                    if (value !== null && value !== undefined && value !== '')
                        normalized[key] = String(value);
                });
                return normalized;
            };

            $scope.isDirty = function isDirty() {
                return !!$scope.editing && !angular.equals(editableFields($scope.editing), editableFields(original));
            };

            var confirmDiscard = function confirmDiscard() {
                return !$scope.isDirty() || $window.confirm($translate.instant('PAM.TEXT_DISCARD_CHANGES'));
            };

            var edit = function edit(platform) {
                platform.settings = platform.settings || {};
                platform.policy = platform.policy || {};
                angular.forEach(platform.storedSecrets, function markStored(name) {
                    platform.settings[name] = STORED_SECRET;
                });
                if (!platform.policy['rotation-mode'])
                    platform.policy['rotation-mode'] = 'never';
                $scope.editing = platform;
                original = angular.copy(platform);
                $scope.saved = false;
                $scope.testResult = null;
            };

            $scope.selectPlatform = function selectPlatform(platform) {
                if (!confirmDiscard())
                    return;
                pamService.getPlatform(platform.id).then(edit, guacNotification.SHOW_REQUEST_ERROR);
            };

            $scope.newPlatform = function newPlatform(type) {
                if (!type || !confirmDiscard())
                    return;
                edit({
                    name        : '',
                    description : '',
                    type        : type,
                    settings    : angular.copy(NEW_PLATFORM_SETTINGS[type] || {}),
                    policy      : { 'rotation-mode' : 'never' }
                });
                original = { type : type };
            };

            $scope.cancelEdit = function cancelEdit() {
                if (confirmDiscard())
                    $scope.editing = original = null;
            };

            /**
             * The editing platform as the server takes it: the secrets still
             * showing as stored are sent empty, keeping their stored value.
             */
            var toSend = function toSend(platform) {
                var sent = angular.copy(platform);
                angular.forEach(platform.storedSecrets, function keepStored(name) {
                    if (sent.settings[name] === STORED_SECRET)
                        delete sent.settings[name];
                });
                return sent;
            };

            /**
             * Steps of the last test of the editing platform, or null.
             */
            $scope.testResult = null;

            /**
             * Whether a test of the editing platform is running.
             */
            $scope.testing = false;

            /**
             * Tests the platform as edited, without saving it.
             */
            $scope.testPlatform = function testPlatform() {
                var tested = $scope.editing;
                $scope.testing = true;
                $scope.testResult = null;
                pamService.testPlatform(toSend(tested)).then(function platformTested(result) {
                    if ($scope.editing === tested)
                        $scope.testResult = result;
                }, guacNotification.SHOW_REQUEST_ERROR)
                ['finally'](function testEnded() {
                    $scope.testing = false;
                });
            };

            $scope.savePlatform = function savePlatform() {
                pamService.savePlatform(toSend($scope.editing)).then(function platformSaved(platform) {
                    edit(platform);
                    $scope.saved = true;
                    loadPlatforms();
                }, guacNotification.SHOW_REQUEST_ERROR);
            };

            $scope.deletePlatform = function deletePlatform() {

                var platform = $scope.editing;

                guacNotification.showStatus({
                    title   : 'PAM.DIALOG_HEADER_DELETE_PLATFORM',
                    text    : {
                        key       : 'PAM.TEXT_CONFIRM_DELETE_PLATFORM',
                        variables : { NAME : platform.name }
                    },
                    actions : [{
                        name      : 'PAM.ACTION_DELETE',
                        className : 'danger',
                        callback  : function confirmDelete() {
                            guacNotification.showStatus(false);
                            pamService.deletePlatform(platform.id).then(function platformDeleted() {
                                $scope.editing = original = null;
                                loadPlatforms();
                            }, guacNotification.SHOW_REQUEST_ERROR);
                        }
                    }, {
                        name     : 'PAM.ACTION_CANCEL',
                        callback : function cancelDelete() {
                            guacNotification.showStatus(false);
                        }
                    }]
                });

            };

            /**
             * Format and version of the files Export writes and Import
             * reads.
             */
            var EXPORT_FORMAT = 'guacamole-pam-platforms';
            var EXPORT_VERSION = 1;

            /**
             * What is exported of a platform: never its secrets, which never
             * leave the server.
             */
            var exported = function exported(platform) {
                var fields = { name : platform.name, type : platform.type };
                if (platform.description)
                    fields.description = platform.description;
                fields.settings = normalize(platform.settings);
                fields.policy = normalize(platform.policy);
                return fields;
            };

            /**
             * Downloads the platforms listed, as filtered, as a JSON file.
             */
            $scope.exportPlatforms = function exportPlatforms() {

                if (!$scope.filteredPlatforms.length)
                    return;

                var file = {
                    format    : EXPORT_FORMAT,
                    version   : EXPORT_VERSION,
                    exported  : new Date().toISOString(),
                    platforms : $scope.filteredPlatforms.map(exported)
                };

                var url = $window.URL.createObjectURL(new $window.Blob([angular.toJson(file, 2) + '\n'],
                        { type : 'application/json' }));
                var link = $window.document.createElement('a');
                link.href = url;
                link.download = 'platforms-' + file.exported.substring(0, 10) + '.json';
                $window.document.body.appendChild(link);
                link.click();
                $window.document.body.removeChild(link);
                $timeout(function releaseFile() { $window.URL.revokeObjectURL(url); }, 0, false);

            };

            /**
             * Names of the platforms of a report with the given outcome, as
             * a list for messages.
             */
            var namesWith = function namesWith(report, outcome) {
                return report.results.filter(function hasOutcome(result) {
                    return result.outcome === outcome;
                }).map(function quote(result) {
                    return '"' + result.name + '"';
                }).join(', ');
            };

            var showRestored = function showRestored(report) {
                var added = namesWith(report, 'CREATED');
                guacNotification.showStatus({
                    title   : 'PAM_PLATFORM_TRANSFER.DIALOG_HEADER_RESTORE_DEFAULTS',
                    text    : added ? { key : 'PAM_PLATFORM_TRANSFER.TEXT_RESTORED', variables : { NAMES : added } }
                                    : { key : 'PAM_PLATFORM_TRANSFER.TEXT_NOTHING_RESTORED',
                                        variables : { NAMES : namesWith(report, 'SKIPPED') } },
                    actions : [{
                        name     : 'PAM.ACTION_CLOSE',
                        callback : function closeRestored() {
                            guacNotification.showStatus(false);
                        }
                    }]
                });
                if (added) {
                    loadPlatforms();
                    loadUsage();
                }
            };

            /**
             * Adds back the default platforms that are missing, once
             * confirmed.
             */
            $scope.restoreDefaults = function restoreDefaults() {
                guacNotification.showStatus({
                    title   : 'PAM_PLATFORM_TRANSFER.DIALOG_HEADER_RESTORE_DEFAULTS',
                    text    : { key : 'PAM_PLATFORM_TRANSFER.TEXT_CONFIRM_RESTORE' },
                    actions : [{
                        name     : 'PAM_PLATFORM_TRANSFER.ACTION_RESTORE',
                        callback : function confirmRestore() {
                            guacNotification.showStatus(false);
                            pamService.restoreDefaultPlatforms().then(showRestored,
                                    guacNotification.SHOW_REQUEST_ERROR);
                        }
                    }, {
                        name     : 'PAM.ACTION_CANCEL',
                        callback : function cancelRestore() {
                            guacNotification.showStatus(false);
                        }
                    }]
                });
            };

            $scope.$watch('editing', function editingChanged() {
                $scope.saved = $scope.saved && !$scope.isDirty();
            }, true);

            // A test tells about the settings it was run with only
            $scope.$watch('editing.settings', function settingsChanged(settings, previous) {
                if (settings !== previous)
                    $scope.testResult = null;
            }, true);

            pamService.getPlatformTypes().then(function typesRetrieved(types) {
                $scope.platformTypes = types;
            }, guacNotification.SHOW_REQUEST_ERROR);

            loadPlatforms();
            loadUsage();

        }]
    };

}]);
