/**
 * The "Approvals" settings tab: requests awaiting approval, with approve and
 * deny actions, and the searchable history of decided requests (sortable,
 * paged, and exportable as CSV, like the checkout history).
 */
angular.module('guacPam').directive('guacSettingsPamApprovals', [function guacSettingsPamApprovals() {

    return {
        restrict    : 'E',
        replace     : true,
        scope       : {},
        templateUrl : 'app/ext/pam/templates/settingsPamApprovals.html',
        controller  : ['$scope', '$injector', function settingsPamApprovalsController($scope, $injector) {

            // Required types
            var SortOrder = $injector.get('SortOrder');

            // Required services
            var $document             = $injector.get('$document');
            var $filter               = $injector.get('$filter');
            var $translate            = $injector.get('$translate');
            var $interval             = $injector.get('$interval');
            var authenticationService = $injector.get('authenticationService');
            var pamApprovalBadge      = $injector.get('pamApprovalBadge');
            var guacNotification      = $injector.get('guacNotification');
            var pamService            = $injector.get('pamService');
            var pamHistoryTools       = $injector.get('pamHistoryTools');

            /**
             * How often the requests awaiting approval refresh, in
             * milliseconds. The history is only searched on demand, so that
             * paging and sorting stay put.
             */
            var REFRESH_INTERVAL = 10000;

            /**
             * Requests awaiting approval, or null while loading.
             */
            $scope.pending = null;

            /**
             * Matching decided requests, each as {entry, decided, decidedBy},
             * or null while loading.
             */
            $scope.history = null;

            /**
             * The decided requests shown on the current page.
             */
            $scope.page = [];

            $scope.searchString = '';

            /**
             * Date format of Guacamole's connection history, for consistency.
             */
            $scope.dateFormat = null;

            $scope.order = new SortOrder([
                '-decided',
                'entry.username',
                'entry.connectionName',
                '-entry.requested',
                'entry.status',
                'decidedBy'
            ]);

            $translate('SETTINGS_CONNECTION_HISTORY.FORMAT_DATE').then(function dateFormatReceived(format) {
                $scope.dateFormat = format;
            }, angular.noop);

            $scope.isLoaded = function isLoaded() {
                return $scope.history !== null && $scope.dateFormat !== null;
            };

            $scope.isEmpty = function isEmpty() {
                return $scope.isLoaded() && $scope.history.length === 0;
            };

            /**
             * Who decided: the approvers of an approved request, otherwise
             * who denied or cancelled it (nobody, for an expired one).
             */
            var getDecidedBy = function getDecidedBy(request) {
                if (request.status === 'APPROVED')
                    return request.approvers.join(', ');
                return request.decidedBy || '';
            };

            /**
             * Searches the history. As for the checkout history, the search
             * string is split into terms, quoted phrases staying whole, and
             * every term must match.
             */
            $scope.search = function search() {

                $scope.history = null;

                var terms = pamHistoryTools.getTerms($scope.searchString);

                pamService.searchApprovals(terms).then(function historyRetrieved(requests) {
                    $scope.history = requests.map(function wrapRequest(request) {
                        return {
                            entry     : request,
                            decided   : request.decided || request.requested,
                            decidedBy : getDecidedBy(request)
                        };
                    });
                }, guacNotification.SHOW_REQUEST_ERROR);

            };

            $scope.downloadCSV = function downloadCSV() {

                var headers = [
                    'PAM_APPROVALS.TABLE_HEADER_REQUESTED_BY',
                    'PAM.TABLE_HEADER_CONNECTION',
                    'PAM_APPROVALS.TABLE_HEADER_ACCOUNT',
                    'PAM.TABLE_HEADER_REASON',
                    'PAM_APPROVALS.TABLE_HEADER_REQUESTED',
                    'PAM_APPROVALS.TABLE_HEADER_APPROVALS_REQUIRED',
                    'PAM_APPROVALS.TABLE_HEADER_DECISION',
                    'PAM_APPROVALS.TABLE_HEADER_DECIDED',
                    'PAM_APPROVALS.TABLE_HEADER_DECIDED_BY',
                    'PAM_APPROVALS.TABLE_HEADER_DENIAL_REASON',
                    'PAM_APPROVALS.FILENAME_CSV'
                ];

                $translate(headers).then(function headersTranslated(translations) {

                    var records = [headers.slice(0, -1).map(function translate(key) {
                        return translations[key];
                    })];

                    angular.forEach($filter('orderBy')($scope.history, $scope.order.predicate),
                            function addRecord(wrapper) {
                        var request = wrapper.entry;
                        records.push([
                            request.username,
                            request.connectionName,
                            request.accountName || '',
                            request.reason,
                            $filter('date')(request.requested, $scope.dateFormat),
                            request.approvalsRequired,
                            request.status,
                            request.decided ? $filter('date')(request.decided, $scope.dateFormat) : '',
                            wrapper.decidedBy,
                            request.decisionReason || ''
                        ]);
                    });

                    pamHistoryTools.saveCsv(records, translations['PAM_APPROVALS.FILENAME_CSV']);

                }, angular.noop);

            };

            /**
             * Identifiers of requests with a decision being sent.
             */
            $scope.busy = {};

            var currentUser = authenticationService.getCurrentUsername();

            var load = function load() {
                pamService.getPendingApprovals().then(function pendingRetrieved(requests) {
                    $scope.pending = requests;
                    pamApprovalBadge.refresh();
                }, guacNotification.SHOW_REQUEST_ERROR);
            };

            /**
             * Whether the current user may decide on a request: not their
             * own, and not already approved by them.
             */
            $scope.canDecide = function canDecide(request) {
                return request.username !== currentUser
                    && request.approvers.indexOf(currentUser) === -1;
            };

            $scope.isOwn = function isOwn(request) {
                return request.username === currentUser;
            };

            /**
             * The request shown in the dialog, as {request, deny, reason},
             * or null when closed.
             */
            $scope.dialog = null;

            $scope.showReason = function showReason(request) {
                $scope.dialog = { request : request, deny : false };
            };

            /**
             * Closes the dialog; when given a click, only one on the
             * backdrop itself.
             */
            $scope.closeDialog = function closeDialog($event) {
                if ($event && $event.target !== $event.currentTarget)
                    return;
                $scope.dialog = null;
            };

            var decide = function decide(request, action) {
                $scope.busy[request.id] = true;
                return action()
                ['catch'](guacNotification.SHOW_REQUEST_ERROR)
                ['finally'](function decided() {
                    delete $scope.busy[request.id];
                    load();
                    $scope.search();
                });
            };

            $scope.approve = function approve(request) {
                decide(request, function sendApproval() {
                    return pamService.approve(request.id);
                });
            };

            /**
             * Asks for the reason of a denial, which the requester sees.
             */
            $scope.deny = function deny(request) {
                $scope.dialog = { request : request, deny : true, reason : '' };
            };

            $scope.confirmDeny = function confirmDeny() {
                var dialog = $scope.dialog;
                decide(dialog.request, function sendDenial() {
                    return pamService.deny(dialog.request.id, dialog.reason.trim()).then(function denied() {
                        if ($scope.dialog === dialog)
                            $scope.dialog = null;
                    });
                });
            };

            var closeOnEscape = function closeOnEscape(e) {
                if (e.key === 'Escape' && $scope.dialog)
                    $scope.$apply(function closeOnEscape() {
                        $scope.dialog = null;
                    });
            };

            $document.on('keydown', closeOnEscape);

            load();
            $scope.search();

            var refresh = $interval(load, REFRESH_INTERVAL);
            $scope.$on('$destroy', function approvalsDestroyed() {
                $interval.cancel(refresh);
                $document.off('keydown', closeOnEscape);
            });

        }]
    };

}]);
