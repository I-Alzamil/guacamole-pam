/**
 * The "Email Templates" tab: the languages emails are written in, each with
 * a subject and text for each kind of email and the messages PAM fills
 * them with. English is built in, and can be changed and restored; others
 * are added, or imported from a file as any language exports. A field left
 * empty takes what English says (what is built in, for English itself),
 * shown in it.
 */
angular.module('guacPam').directive('guacSettingsPamEmailTemplates', [function guacSettingsPamEmailTemplates() {

    return {
        restrict    : 'E',
        replace     : true,
        scope       : {},
        templateUrl : 'app/ext/pam/templates/settingsPamEmailTemplates.html',
        controller  : ['$scope', '$injector', '$element', function settingsPamEmailTemplatesController($scope,
                $injector, $element) {

            var $q               = $injector.get('$q');
            var $timeout         = $injector.get('$timeout');
            var $window          = $injector.get('$window');
            var $translate       = $injector.get('$translate');
            var guacNotification = $injector.get('guacNotification');
            var pamFilterText    = $injector.get('pamFilterText');
            var pamService       = $injector.get('pamService');

            /**
             * Kinds of email, as languages name them.
             */
            $scope.kinds = ['approval', 'decision', 'ended', 'other'];

            /**
             * The placeholders of templates and messages, as EmailTemplates
             * lists them.
             */
            $scope.placeholders = ['summary', 'details', 'action', 'link', 'why', 'event', 'user', 'actor',
                'connection', 'connection-id', 'request', 'checkout', 'minutes', 'approvals',
                'approvals-required', 'starts', 'ends', 'reason', 'detail', 'client-address', 'server', 'time'];

            /**
             * Every language, or null while loading.
             */
            $scope.languages = null;

            /**
             * The languages matching the filter, and what it matches: their
             * name, code and state as shown.
             */
            $scope.filteredLanguages = [];
            $scope.filteredLanguageProperties = ['pamFilterText'];

            /**
             * English as built in, to translate from.
             */
            $scope.builtIn = null;

            /**
             * The keys of messages, as English has them.
             */
            $scope.messageKeys = [];

            /**
             * The messages, as { key }, those matching the filter, and what
             * it matches: their key and English text.
             */
            $scope.messages = [];
            $scope.filteredMessages = [];
            $scope.filteredMessageProperties = ['pamFilterText'];

            /**
             * The language being edited: its code when loaded ("original",
             * null for a new one) and its fields ("language"), only those
             * differing from "base", what empty fields take.
             */
            $scope.editing = null;

            $scope.base = null;

            /**
             * The previews of each kind, by kind.
             */
            $scope.previews = {};

            $scope.saving = false;

            $scope.previewing = false;

            var closeStatus = {
                name     : 'PAM.ACTION_CLOSE',
                callback : function closeStatus() { guacNotification.showStatus(false); }
            };

            var reload = function reload() {
                return pamService.getEmailLanguages().then(function languagesRead(languages) {
                    angular.forEach(languages, function addFilterText(language) {
                        pamFilterText(language, [language.name, language.code, $translate.instant(language.builtIn
                                ? (language.changed ? 'PAM_EMAIL_TEMPLATES.INFO_BUILT_IN_CHANGED'
                                    : 'PAM_EMAIL_TEMPLATES.INFO_BUILT_IN') : 'PAM_EMAIL_TEMPLATES.INFO_ADDED'),
                            language.modifiedBy]);
                    });
                    $scope.languages = languages;
                }, guacNotification.SHOW_REQUEST_ERROR);
            };

            pamService.getBuiltInEmailLanguage().then(function builtInRead(builtIn) {
                $scope.builtIn = builtIn;
                $scope.messageKeys = Object.keys(builtIn.messages);
                $scope.messages = $scope.messageKeys.map(function message(key) {
                    return pamFilterText({ key : key }, [key, builtIn.messages[key]]);
                });
            }, guacNotification.SHOW_REQUEST_ERROR);
            reload();

            /**
             * A language with only what differs from the base: messages and
             * templates equal to it are left empty, as they take it.
             */
            var differences = function differences(language, base) {
                var edited = { code : language.code, name : language.name, messages : {}, templates : {} };
                angular.forEach(language.messages, function keepMessage(text, key) {
                    if (text !== base.messages[key])
                        edited.messages[key] = text;
                });
                angular.forEach($scope.kinds, function keepTemplate(kind) {
                    var own = language.templates[kind] || {};
                    var theirs = base.templates[kind] || {};
                    edited.templates[kind] = {
                        subject : own.subject !== theirs.subject ? own.subject : '',
                        body    : own.body !== theirs.body ? own.body : ''
                    };
                });
                return edited;
            };

            /**
             * What empty fields of a language take: English as built in for
             * English, English as in effect for others.
             */
            var baseOf = function baseOf(code) {
                return code === 'en' ? $q.when($scope.builtIn) : pamService.getEmailLanguage('en');
            };

            $scope.newLanguage = function newLanguage() {
                baseOf(null).then(function baseRead(base) {
                    $scope.base = base;
                    $scope.previews = {};
                    $scope.editing = { original : null, language : differences(
                        { code : '', name : '', messages : {}, templates : {} }, base) };
                }, guacNotification.SHOW_REQUEST_ERROR);
            };

            $scope.editLanguage = function editLanguage(summary) {
                $q.all([pamService.getEmailLanguage(summary.code), baseOf(summary.code)])
                .then(function languageRead(results) {
                    $scope.base = results[1];
                    $scope.previews = {};
                    $scope.editing = { original : summary.code, language : differences(results[0], results[1]) };
                }, guacNotification.SHOW_REQUEST_ERROR);
            };

            $scope.cancel = function cancel() {
                $scope.editing = null;
            };

            /**
             * The language as sent: its non-empty fields only.
             */
            var toSend = function toSend(language) {
                var sent = { code : language.code, name : language.name, messages : {}, templates : {} };
                angular.forEach(language.messages, function sendMessage(text, key) {
                    if (text)
                        sent.messages[key] = text;
                });
                angular.forEach(language.templates, function sendTemplate(template, kind) {
                    if (template.subject || template.body)
                        sent.templates[kind] = { subject : template.subject || null, body : template.body || null };
                });
                return sent;
            };

            var showSaved = function showSaved() {
                guacNotification.showStatus({
                    title   : 'PAM.TAB_EMAIL_TEMPLATES',
                    text    : { key : 'PAM.INFO_SAVED' },
                    actions : [ closeStatus ]
                });
            };

            var save = function save(language) {
                $scope.saving = true;
                return pamService.saveEmailLanguage(language).then(function saved() {
                    $scope.editing = null;
                    showSaved();
                    return reload();
                }, guacNotification.SHOW_REQUEST_ERROR)['finally'](function saveEnded() {
                    $scope.saving = false;
                });
            };

            var exists = function exists(code) {
                return ($scope.languages || []).some(function sameCode(language) {
                    return language.code === code;
                });
            };

            /**
             * Asks before replacing a language of the same code, then runs
             * the given function.
             */
            var unlessReplacing = function unlessReplacing(code, then) {
                if (!exists(code)) {
                    then();
                    return;
                }
                guacNotification.showStatus({
                    title   : 'PAM_EMAIL_TEMPLATES.DIALOG_HEADER_REPLACE',
                    text    : { key : 'PAM_EMAIL_TEMPLATES.TEXT_CONFIRM_REPLACE', variables : { CODE : code } },
                    actions : [{
                        name      : 'PAM_EMAIL_TEMPLATES.ACTION_REPLACE',
                        className : 'danger',
                        callback  : function confirmReplace() {
                            guacNotification.showStatus(false);
                            then();
                        }
                    }, {
                        name     : 'PAM.ACTION_CANCEL',
                        callback : function cancelReplace() { guacNotification.showStatus(false); }
                    }]
                });
            };

            $scope.save = function saveLanguage() {
                var language = toSend($scope.editing.language);
                if ($scope.editing.original)
                    save(language);
                else
                    unlessReplacing(language.code, function replace() { save(language); });
            };

            $scope.preview = function preview(kind) {
                $scope.previewing = true;
                var language = toSend($scope.editing.language);
                language.code = language.code || 'xx';
                language.name = language.name || '-';
                pamService.previewEmailLanguage(language, kind).then(function previewed(result) {
                    $scope.previews[kind] = result;
                }, guacNotification.SHOW_REQUEST_ERROR)['finally'](function previewEnded() {
                    $scope.previewing = false;
                });
            };

            /**
             * Downloads a language, complete, as a JSON file.
             */
            $scope.exportLanguage = function exportLanguage(summary) {
                pamService.getEmailLanguage(summary.code).then(function languageRead(language) {
                    var url = $window.URL.createObjectURL(new $window.Blob([angular.toJson(language, 2) + '\n'],
                            { type : 'application/json' }));
                    var link = $window.document.createElement('a');
                    link.href = url;
                    link.download = 'email-' + language.code + '.json';
                    $window.document.body.appendChild(link);
                    link.click();
                    $window.document.body.removeChild(link);
                    $timeout(function releaseFile() { $window.URL.revokeObjectURL(url); }, 0, false);
                }, guacNotification.SHOW_REQUEST_ERROR);
            };

            /**
             * The file input of imports, hidden, opened by the Import
             * button.
             */
            var fileInput = $element[0].querySelector('.pam-email-import');

            $scope.chooseImport = function chooseImport() {
                fileInput.value = '';
                fileInput.click();
            };

            fileInput.addEventListener('change', function fileChosen() {
                var file = fileInput.files && fileInput.files[0];
                if (!file)
                    return;
                var reader = new $window.FileReader();
                reader.onload = function fileRead() {
                    $scope.$apply(function importFile() {
                        var language;
                        try {
                            language = JSON.parse(reader.result);
                        }
                        catch (e) {
                            guacNotification.showStatus({
                                className : 'error',
                                title     : 'PAM_EMAIL_TEMPLATES.DIALOG_HEADER_IMPORT',
                                text      : { key : 'PAM_EMAIL_TEMPLATES.TEXT_NOT_JSON' },
                                actions   : [ closeStatus ]
                            });
                            return;
                        }
                        if (!language || typeof language.code !== 'string') {
                            guacNotification.showStatus({
                                className : 'error',
                                title     : 'PAM_EMAIL_TEMPLATES.DIALOG_HEADER_IMPORT',
                                text      : { key : 'PAM_EMAIL_TEMPLATES.TEXT_NOT_LANGUAGE' },
                                actions   : [ closeStatus ]
                            });
                            return;
                        }
                        unlessReplacing(language.code, function replace() { save(language); });
                    });
                };
                reader.readAsText(file);
            });

            var confirm = function confirm(title, text, action, then) {
                guacNotification.showStatus({
                    title   : title,
                    text    : text,
                    actions : [{
                        name      : action,
                        className : 'danger',
                        callback  : function confirmed() {
                            guacNotification.showStatus(false);
                            pamService.deleteEmailLanguage(then).then(function deleted() {
                                if ($scope.editing && $scope.editing.original === then)
                                    $scope.editing = null;
                                return reload();
                            }, guacNotification.SHOW_REQUEST_ERROR);
                        }
                    }, {
                        name     : 'PAM.ACTION_CANCEL',
                        callback : function cancelled() { guacNotification.showStatus(false); }
                    }]
                });
            };

            $scope.deleteLanguage = function deleteLanguage(summary) {
                confirm('PAM_EMAIL_TEMPLATES.DIALOG_HEADER_DELETE', {
                    key       : 'PAM_EMAIL_TEMPLATES.TEXT_CONFIRM_DELETE',
                    variables : { NAME : summary.name, USERS : summary.users }
                }, 'PAM.ACTION_DELETE', summary.code);
            };

            $scope.restoreLanguage = function restoreLanguage(summary) {
                confirm('PAM_EMAIL_TEMPLATES.DIALOG_HEADER_RESTORE', {
                    key : 'PAM_EMAIL_TEMPLATES.TEXT_CONFIRM_RESTORE'
                }, 'PAM_EMAIL_TEMPLATES.ACTION_RESTORE', summary.code);
            };

        }]
    };

}]);
