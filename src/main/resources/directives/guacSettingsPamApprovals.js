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
             * Matching decided requests, each as {entry, decided, decidedBy,
             * accessType}, or null while loading.
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
                'accessType',
                'entry.starts',
                'entry.ends',
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
             * Where who decided did so from: each approver's address, for an
             * approved request, otherwise that of who denied or cancelled it.
             */
            var decidedFrom = function decidedFrom(request) {
                if (request.status === 'APPROVED')
                    return request.approvals.map(function approvalFrom(approval) {
                        return approval.approver + ' (' + (approval.remoteHost || '?') + ')';
                    }).join(', ');
                return request.decidedHost || '';
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
                            decidedBy : getDecidedBy(request),
                            accessType : $scope.accessType(request)
                        };
                    });
                }, guacNotification.SHOW_REQUEST_ERROR);

            };

            /**
             * Saves the history as CSV, with its times in ISO 8601: in the
             * browser's time zone, with its offset from UTC, so they stay
             * unambiguous wherever the file is read.
             */
            $scope.downloadCSV = function downloadCSV() {

                var headers = [
                    'PAM_APPROVALS.TABLE_HEADER_REQUESTED_BY',
                    'PAM.TABLE_HEADER_CONNECTION',
                    'PAM_APPROVALS.TABLE_HEADER_ACCOUNT',
                    'PAM.TABLE_HEADER_REASON',
                    'PAM_APPROVALS.TABLE_HEADER_REQUESTED',
                    'PAM_APPROVALS.TABLE_HEADER_REQUESTED_FROM',
                    'PAM_APPROVALS.TABLE_HEADER_ACCESS_TYPE',
                    'PAM_APPROVALS.TABLE_HEADER_ACCESS_FROM',
                    'PAM_APPROVALS.TABLE_HEADER_ACCESS_TO',
                    'PAM_APPROVALS.TABLE_HEADER_PERIODS',
                    'PAM_APPROVALS.TABLE_HEADER_EXTENDS_BY_MINUTES',
                    'PAM_APPROVALS.TABLE_HEADER_APPROVALS_REQUIRED',
                    'PAM_APPROVALS.TABLE_HEADER_DECISION',
                    'PAM_APPROVALS.TABLE_HEADER_DECIDED',
                    'PAM_APPROVALS.TABLE_HEADER_DECIDED_BY',
                    'PAM_APPROVALS.TABLE_HEADER_DECIDED_FROM',
                    'PAM_APPROVALS.TABLE_HEADER_DENIAL_REASON',
                    'PAM_APPROVALS.FILENAME_CSV'
                ];

                $translate(headers.concat(['PAM_APPROVALS.ACCESS_TYPE_IMMEDIATE', 'PAM_APPROVALS.ACCESS_TYPE_SCHEDULED',
                        'PAM_APPROVALS.ACCESS_TYPE_EXTENSION']))
                .then(function headersTranslated(translations) {

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
                            $filter('pamLocalIso')(request.requested),
                            request.remoteHost || '',
                            translations['PAM_APPROVALS.ACCESS_TYPE_' + $scope.accessType(request)],
                            $filter('pamLocalIso')(request.starts),
                            $filter('pamLocalIso')(request.ends),
                            request.periods,
                            request.extensionMinutes || '',
                            request.approvalsRequired,
                            request.status,
                            $filter('pamLocalIso')(request.decided),
                            wrapper.decidedBy,
                            decidedFrom(request),
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

            /**
             * What a request asks for: "IMMEDIATE" access, "SCHEDULED"
             * access, or an "EXTENSION" of a checkout.
             */
            $scope.accessType = function accessType(request) {
                if (request.extendsCheckout)
                    return 'EXTENSION';
                return request.starts ? 'SCHEDULED' : 'IMMEDIATE';
            };

            /**
             * Whether the access a request asks for has details beyond its
             * type: its time, its duration, or the extension.
             */
            $scope.hasAccessDetails = function hasAccessDetails(request) {
                return !!request.starts || request.periods > 1 || !!request.extendsCheckout;
            };

            $scope.isOwn = function isOwn(request) {
                return request.username === currentUser;
            };

            /**
             * Whether the request, approved ahead of time, ended without its
             * requester checking out with it.
             */
            $scope.isUnused = function isUnused(request) {
                return request.status === 'APPROVED' && !!request.starts && !request.checkoutId
                    && request.ends <= Date.now();
            };

            /**
             * The request shown in the dialog, as {request, deny, reason}, or
             * {request, details} for its details, or null when closed.
             */
            $scope.dialog = null;

            $scope.showReason = function showReason(request) {
                $scope.dialog = { request : request, deny : false };
            };

            /**
             * Shows details of a request: "access" (its scheduled access),
             * "requester", or "decision" (who approved, denied or cancelled
             * it), with where they did so from.
             */
            $scope.showDetails = function showDetails(request, details) {
                $scope.dialog = { request : request, details : details };
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
                    dialog.error = null;
                    return pamService.deny(dialog.request.id, dialog.reason.trim()).then(function denied() {
                        if ($scope.dialog === dialog)
                            $scope.dialog = null;
                    }, function denialFailed(error) {
                        // Shown in the dialog, as Guacamole's own would be
                        // under it
                        dialog.error = (error && error.message) || 'Request failed.';
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
