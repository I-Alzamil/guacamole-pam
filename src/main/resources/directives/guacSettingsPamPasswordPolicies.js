/**
 * The "Password Policies" tab: named rules of generated passwords, which
 * platforms and connections choose, with examples and their strength while
 * editing.
 */
angular.module('guacPam').directive('guacSettingsPamPasswordPolicies', [function guacSettingsPamPasswordPolicies() {

    return {
        restrict    : 'E',
        replace     : true,
        scope       : {},
        templateUrl : 'app/ext/pam/templates/settingsPamPasswordPolicies.html',
        controller  : ['$scope', '$injector', function settingsPamPasswordPoliciesController($scope, $injector) {

            // Required services
            var $timeout         = $injector.get('$timeout');
            var $translate       = $injector.get('$translate');
            var $window          = $injector.get('$window');
            var guacNotification = $injector.get('guacNotification');
            var pamService       = $injector.get('pamService');

            /**
             * Characters with a meaning to shells or cmd.exe, which break a
             * password a sequence script places on a command line.
             */
            var SHELL_SPECIAL = '\'"`$\\!;&|<>()*?[]{}~#%^';

            /**
             * Bits of strength below which passwords are weak, and below
             * which they are fair.
             */
            var WEAK_BITS = 60;
            var FAIR_BITS = 80;

            /**
             * The rules of passwords without a policy, from the server, or
             * null while loading. New policies start from them.
             */
            $scope.defaultRules = null;

            /**
             * The kinds of characters, in the order shown.
             */
            $scope.kinds = [
                { allowed : 'lowercase', minimum : 'minLowercase', key : 'LOWERCASE' },
                { allowed : 'uppercase', minimum : 'minUppercase', key : 'UPPERCASE' },
                { allowed : 'digits', minimum : 'minDigits', key : 'DIGITS' },
                { allowed : 'symbols', minimum : 'minSymbols', key : 'SYMBOLS' }
            ];

            /**
             * The policies, or null while loading.
             */
            $scope.policies = null;

            /**
             * The policy being edited (a copy), or null.
             */
            $scope.editing = null;

            /**
             * Examples of the rules being edited, as { examples, bits }, the
             * error making none, and whether they are being made.
             */
            $scope.preview = null;
            $scope.previewError = null;

            var original = null;

            var loadPolicies = function loadPolicies() {
                return pamService.getPasswordPolicies().then(function policiesRetrieved(policies) {
                    $scope.policies = policies;
                }, guacNotification.SHOW_REQUEST_ERROR);
            };

            /**
             * A summary of rules, as the list shows them: their length and
             * the kinds of characters allowed.
             */
            $scope.summary = function summary(rules) {
                var kinds = $scope.kinds.filter(function isAllowed(kind) {
                    return rules[kind.allowed];
                }).map(function name(kind) {
                    return $translate.instant('PAM_PASSWORD_POLICIES.KIND_' + kind.key).toLowerCase();
                });
                return $translate.instant('PAM_PASSWORD_POLICIES.TEXT_SUMMARY',
                        { LENGTH : rules.length, KINDS : kinds.join(', ') });
            };

            $scope.isDirty = function isDirty() {
                return $scope.editing && !angular.equals($scope.editing, original);
            };

            $scope.newPolicy = function newPolicy() {
                if (!$scope.isDirty() || $window.confirm($translate.instant('PAM.TEXT_DISCARD_CHANGES'))) {
                    $scope.editing = { name : '', description : '', rules : angular.copy($scope.defaultRules) };
                    original = angular.copy($scope.editing);
                }
            };

            /**
             * Shows the built-in default, which cannot be changed.
             */
            $scope.viewDefault = function viewDefault() {
                if (!$scope.isDirty() || $window.confirm($translate.instant('PAM.TEXT_DISCARD_CHANGES'))) {
                    $scope.editing = {
                        builtIn     : true,
                        name        : $translate.instant('PAM_PASSWORD_POLICIES.NAME_DEFAULT'),
                        description : $translate.instant('PAM_PASSWORD_POLICIES.TEXT_DEFAULT_DESCRIPTION'),
                        rules       : angular.copy($scope.defaultRules)
                    };
                    original = angular.copy($scope.editing);
                }
            };

            $scope.editPolicy = function editPolicy(policy) {
                if (!$scope.isDirty() || $window.confirm($translate.instant('PAM.TEXT_DISCARD_CHANGES'))) {
                    $scope.editing = {
                        id          : policy.id,
                        name        : policy.name,
                        description : policy.description || '',
                        rules       : angular.extend(angular.copy($scope.defaultRules), policy.rules),
                        platforms   : policy.platforms,
                        connections : policy.connections
                    };
                    original = angular.copy($scope.editing);
                }
            };

            $scope.cancel = function cancel() {
                if (!$scope.isDirty() || $window.confirm($translate.instant('PAM.TEXT_DISCARD_CHANGES')))
                    $scope.editing = original = null;
            };

            $scope.save = function save() {
                var policy = {
                    id          : $scope.editing.id,
                    name        : $scope.editing.name,
                    description : $scope.editing.description,
                    rules       : $scope.editing.rules
                };
                var saved = policy.id ? pamService.updatePasswordPolicy(policy)
                                      : pamService.createPasswordPolicy(policy);
                saved.then(function policySaved() {
                    $scope.editing = original = null;
                    loadPolicies();
                }, guacNotification.SHOW_REQUEST_ERROR);
            };

            $scope.deletePolicy = function deletePolicy(policy) {
                guacNotification.showStatus({
                    title   : 'PAM_PASSWORD_POLICIES.DIALOG_HEADER_DELETE',
                    text    : { key : 'PAM_PASSWORD_POLICIES.TEXT_CONFIRM_DELETE', variables : { NAME : policy.name } },
                    actions : [{
                        name      : 'PAM.ACTION_DELETE',
                        className : 'danger',
                        callback  : function confirmDelete() {
                            guacNotification.showStatus(false);
                            pamService.deletePasswordPolicy(policy.id).then(function policyDeleted() {
                                if ($scope.editing && $scope.editing.id === policy.id)
                                    $scope.editing = original = null;
                                loadPolicies();
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
             * How strong passwords of the given bits are: "WEAK", "FAIR" or
             * "STRONG".
             */
            $scope.strength = function strength(bits) {
                return bits < WEAK_BITS ? 'WEAK' : bits < FAIR_BITS ? 'FAIR' : 'STRONG';
            };

            /**
             * The symbols chosen that break a password on a command line.
             */
            $scope.shellSpecial = function shellSpecial() {
                var rules = $scope.editing && $scope.editing.rules;
                if (!rules || !rules.symbols)
                    return '';
                return (rules.symbolSet || '').split('').filter(function isSpecial(c) {
                    return SHELL_SPECIAL.indexOf(c) >= 0;
                }).join(' ');
            };

            /**
             * Makes new examples of the rules being edited.
             */
            $scope.refreshPreview = function refreshPreview() {
                if (!$scope.editing)
                    return;
                var rules = angular.copy($scope.editing.rules);
                pamService.getExamplePasswords(rules).then(function examplesRetrieved(preview) {
                    if ($scope.editing && angular.equals(rules, $scope.editing.rules)) {
                        $scope.preview = preview;
                        $scope.previewError = null;
                    }
                }, function examplesFailed(error) {
                    if ($scope.editing && angular.equals(rules, $scope.editing.rules)) {
                        $scope.preview = null;
                        $scope.previewError = error && error.message;
                    }
                });
            };

            // Shortly after the rules stop changing
            var pending = null;
            $scope.$watch('editing.rules', function rulesChanged(rules) {
                $timeout.cancel(pending);
                if (!rules) {
                    $scope.preview = $scope.previewError = null;
                    return;
                }
                pending = $timeout($scope.refreshPreview, 300);
            }, true);

            $scope.$on('$destroy', function policiesDestroyed() {
                $timeout.cancel(pending);
            });

            pamService.getDefaultPasswordRules().then(function defaultRetrieved(rules) {
                $scope.defaultRules = rules;
            }, guacNotification.SHOW_REQUEST_ERROR);

            loadPolicies();

        }]
    };

}]);
