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
            var $window          = $injector.get('$window');
            var guacNotification = $injector.get('guacNotification');
            var pamService       = $injector.get('pamService');

            /**
             * Settings of new platforms, by type.
             */
            var NEW_PLATFORM_SETTINGS = {
                ssh : {
                    script : '# Each line is sent to the target, followed by Enter.\n'
                           + '# @expect waits until the output contains the given text.\n'
                           + 'passwd\n'
                           + '@expect assword:\n'
                           + '<OLDPASS>\n'
                           + '@expect assword:\n'
                           + '<NEWPASS>\n'
                           + '@expect assword:\n'
                           + '<NEWPASS>\n'
                }
            };

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

            var loadPlatforms = function loadPlatforms() {
                return pamService.getPlatforms().then(function platformsRetrieved(platforms) {
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
                if (!platform.policy['rotation-mode'])
                    platform.policy['rotation-mode'] = 'never';
                $scope.editing = platform;
                original = angular.copy(platform);
                $scope.saved = false;
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

            $scope.savePlatform = function savePlatform() {
                pamService.savePlatform($scope.editing).then(function platformSaved(platform) {
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

            $scope.$watch('editing', function editingChanged() {
                $scope.saved = $scope.saved && !$scope.isDirty();
            }, true);

            pamService.getPlatformTypes().then(function typesRetrieved(types) {
                $scope.platformTypes = types;
            }, guacNotification.SHOW_REQUEST_ERROR);

            loadPlatforms();
            loadUsage();

        }]
    };

}]);
