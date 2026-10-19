/**
 * History of every checkout, active or ended, with search, sorting, paging
 * and CSV export, shown on the "Checkouts" tab. Modeled on Guacamole's own
 * connection history tab.
 */
angular.module('guacPam').directive('guacSettingsPamHistory', [function guacSettingsPamHistory() {

    return {
        restrict    : 'E',
        replace     : true,
        scope       : {},
        templateUrl : 'app/ext/pam/templates/settingsPamHistory.html',
        controller  : ['$scope', '$injector', function settingsPamHistoryController($scope, $injector) {

            // Required types
            var SortOrder = $injector.get('SortOrder');

            // Required services
            var $filter          = $injector.get('$filter');
            var $translate       = $injector.get('$translate');
            var guacNotification = $injector.get('guacNotification');
            var pamService       = $injector.get('pamService');
            var pamHistoryTools  = $injector.get('pamHistoryTools');

            /**
             * Matching checkouts, each as {entry, duration, ended}, or null
             * while loading.
             */
            $scope.checkouts = null;

            /**
             * The checkouts shown on the current page.
             */
            $scope.page = [];

            $scope.searchString = '';

            /**
             * Date format of Guacamole's connection history, for consistency.
             */
            $scope.dateFormat = null;

            $scope.order = new SortOrder([
                '-entry.checkedOut',
                'entry.username',
                'entry.connectionName',
                '-duration',
                'ended',
                '-entry.revealCount'
            ]);

            $translate('SETTINGS_CONNECTION_HISTORY.FORMAT_DATE').then(function dateFormatReceived(format) {
                $scope.dateFormat = format;
            }, angular.noop);

            $scope.isLoaded = function isLoaded() {
                return $scope.checkouts !== null && $scope.dateFormat !== null;
            };

            $scope.isEmpty = function isEmpty() {
                return $scope.isLoaded() && $scope.checkouts.length === 0;
            };

            /**
             * How long a checkout lasted, in milliseconds, up to now if it
             * is still active.
             */
            var getDuration = function getDuration(checkout) {
                return Math.max(0, (checkout.released || Date.now()) - checkout.checkedOut);
            };

            /**
             * A duration as "45 s", "12 min", "2 h 5 min" or "3 d 4 h".
             */
            $scope.formatDuration = function formatDuration(milliseconds) {
                var seconds = Math.round(milliseconds / 1000);
                if (seconds < 60)
                    return seconds + ' s';
                var minutes = Math.floor(seconds / 60);
                if (minutes < 60)
                    return minutes + ' min';
                var hours = Math.floor(minutes / 60);
                if (hours < 24)
                    return hours + ' h' + (minutes % 60 ? ' ' + (minutes % 60) + ' min' : '');
                return Math.floor(hours / 24) + ' d' + (hours % 24 ? ' ' + (hours % 24) + ' h' : '');
            };

            /**
             * Translation key describing how a checkout ended, or that it is
             * still active.
             */
            $scope.endKey = function endKey(checkout) {
                return checkout.released ? 'PAM.RELEASE_' + checkout.releaseReason : 'PAM.INFO_ACTIVE';
            };

            /**
             * Searches the history. Like Guacamole's history, the search
             * string is split into terms, quoted phrases staying whole, and
             * every term must match.
             */
            $scope.search = function search() {

                $scope.checkouts = null;

                var terms = pamHistoryTools.getTerms($scope.searchString);

                pamService.searchCheckouts(terms).then(function checkoutsRetrieved(checkouts) {
                    $scope.checkouts = checkouts.map(function wrapCheckout(checkout) {
                        return {
                            entry    : checkout,
                            duration : getDuration(checkout),
                            ended    : checkout.released ? 1 : 0
                        };
                    });
                }, guacNotification.SHOW_REQUEST_ERROR);

            };

            $scope.downloadCSV = function downloadCSV() {

                var headers = [
                    'PAM.TABLE_HEADER_USER',
                    'PAM.TABLE_HEADER_CONNECTION',
                    'PAM.TABLE_HEADER_REASON',
                    'PAM.TABLE_HEADER_CHECKED_OUT',
                    'PAM.TABLE_HEADER_EXPIRES',
                    'PAM.TABLE_HEADER_ENDED',
                    'PAM_HISTORY.TABLE_HEADER_ENDED_HOW',
                    'PAM_HISTORY.TABLE_HEADER_ENDED_BY',
                    'PAM_HISTORY.TABLE_HEADER_DURATION_SECONDS',
                    'PAM.TABLE_HEADER_VIEWS',
                    'PAM_HISTORY.TABLE_HEADER_EXCLUSIVE',
                    'PAM_HISTORY.TABLE_HEADER_APPROVED_BY',
                    'PAM_HISTORY.FILENAME_CSV'
                ];

                $translate(headers).then(function headersTranslated(translations) {

                    var records = [headers.slice(0, -1).map(function translate(key) {
                        return translations[key];
                    })];

                    angular.forEach($filter('orderBy')($scope.checkouts, $scope.order.predicate),
                            function addRecord(wrapper) {
                        var checkout = wrapper.entry;
                        records.push([
                            checkout.username,
                            checkout.connectionName,
                            checkout.reason,
                            $filter('date')(checkout.checkedOut, $scope.dateFormat),
                            $filter('date')(checkout.expires, $scope.dateFormat),
                            checkout.released ? $filter('date')(checkout.released, $scope.dateFormat) : '',
                            checkout.releaseReason || '',
                            checkout.releasedBy || '',
                            Math.round(wrapper.duration / 1000),
                            checkout.revealCount,
                            checkout.exclusive,
                            (checkout.approvedBy || []).join(', ')
                        ]);
                    });

                    pamHistoryTools.saveCsv(records, translations['PAM_HISTORY.FILENAME_CSV']);

                }, angular.noop);

            };

            $scope.search();

            // A checkout was revoked on the same tab
            $scope.$on('pamCheckoutsChanged', $scope.search);

        }]
    };

}]);
