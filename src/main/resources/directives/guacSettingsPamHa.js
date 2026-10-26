/**
 * The "High Availability" tab of the settings, for administrators, when the
 * HA module runs: the servers sharing the database, as each last reported
 * in, what this server shares, and what looks wrong.
 */
angular.module('guacPam').directive('guacSettingsPamHa', [function guacSettingsPamHa() {

    return {
        restrict    : 'E',
        replace     : true,
        scope       : {},
        templateUrl : 'app/ext/pam/templates/settingsPamHa.html',
        controller  : ['$scope', '$injector', function settingsPamHaController($scope, $injector) {

            var $interval    = $injector.get('$interval');
            var $routeParams = $injector.get('$routeParams');
            var pamHaService = $injector.get('pamHaService');

            /**
             * How often the status is read again, in milliseconds.
             */
            var REFRESH_MS = 10000;

            $scope.dataSource = $routeParams.dataSource;
            $scope.status = null;
            $scope.error = null;
            $scope.checking = false;

            /**
             * What checking each server's URL found, by server, kept until
             * checked again.
             */
            $scope.reach = {};

            /**
             * What looks wrong, as translation keys, and what this server
             * shares, as of the status last read.
             */
            $scope.warnings = [];
            $scope.features = [];

            var warnings = function warnings(status) {

                if (status.error)
                    return [];

                var found = [];
                var versions = {};
                var running = status.servers.filter(function isRunning(server) {
                    return server.alive;
                });
                running.forEach(function addVersion(server) {
                    versions[server.version || '?'] = true;
                });

                if (running.length < 2)
                    found.push('PAM_HA.WARNING_ALONE');
                if (Object.keys(versions).length > 1)
                    found.push('PAM_HA.WARNING_VERSIONS');
                if (!status.settings.url)
                    found.push('PAM_HA.WARNING_NO_URL');
                if (status.settings.recordingStorage && !status.shared.recordings)
                    found.push('PAM_HA.WARNING_RECORDINGS');
                if (!status.shared.logins)
                    found.push('PAM_HA.WARNING_LOGINS');

                return found;

            };

            /**
             * What this server shares, in the order shown, with whether the
             * extension it applies to is installed.
             */
            var features = function features(status) {
                return [
                    { name : 'SESSIONS',    shared : status.shared.sessions,   applies : true },
                    { name : 'LOGINS',      shared : status.shared.logins,     applies : true },
                    { name : 'SHARE_LINKS', shared : status.shared.shareLinks, applies : true },
                    { name : 'BANS',        shared : status.shared.bans,       applies : status.settings.ban },
                    { name : 'TOTP',        shared : status.shared.totp,       applies : status.settings.totp },
                    { name : 'RECORDINGS',  shared : status.shared.recordings, applies : status.settings.recordingStorage }
                ];
            };

            var load = function load(check) {
                return pamHaService.getStatus($scope.dataSource, check).then(function statusRead(status) {
                    $scope.status = status;
                    $scope.error = null;
                    $scope.warnings = warnings(status);
                    $scope.features = features(status);
                    if (check) {
                        $scope.reach = {};
                        status.servers.forEach(function addReach(server) {
                            if (server.reach)
                                $scope.reach[server.id] = server.reach;
                        });
                    }
                }, function statusFailed(error) {
                    $scope.error = error;
                });
            };

            $scope.isLoaded = function isLoaded() {
                return $scope.status !== null || $scope.error !== null;
            };

            $scope.check = function check() {
                $scope.checking = true;
                load(true)['finally'](function checked() {
                    $scope.checking = false;
                });
            };

            load(false);
            var refresh = $interval(function reload() {
                load(false);
            }, REFRESH_MS);

            $scope.$on('$destroy', function stopRefreshing() {
                $interval.cancel(refresh);
            });

        }]
    };

}]);
