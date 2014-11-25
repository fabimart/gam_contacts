
# gam_contacts.py : add the contacts funcionality to GAM
#
# history
# 2014-11-25 - fabiano.martins@trt4.jus.br - first functional version

# Requires: python-httplib2, python-uri-templates, pythopn-gdata

from __builtin__ import RuntimeError
import json
import optparse
import os
import sys
import time

import gdata.contacts.client
import gdata.gauth
import httplib2

# imports oauth2client, with fallback to 'GAM-XX' subdirectory
try:
    import oauth2client.client
except ImportError:
    fallbackdir = os.path.join(os.path.dirname(__file__), 'GAM-3.42')
    fallbackdir = os.path.normpath(fallbackdir)
    sys.path.append(fallbackdir)
    import oauth2client.client


class GoogleUser(object):
    def __init__(self, user_id):
        self.user_id = user_id
        self.contact_feeds = None
        self.contacts_service = None

    # TODO: revise
    def contact_delete(self, contact):
        which_feed = contact / len(self.contact_feeds[0].entry)
        contact_on_feed = contact - (which_feed * len(self.contact_feeds[0].entry))

        if contact_on_feed >= len(self.contact_feeds[which_feed].entry):
            raise RuntimeError("Internal error: contact %d out of bounds of array contact_feeds[%d] (%d)" % (contact_on_feed, which_feed, len(self.contact_feeds[which_feed].entry)))

        mail = ''

        for mailtmp in self.contact_feeds[which_feed].entry[contact_on_feed].email:
            mail = mailtmp.address
        print 'removendo contact %s' % mail
        if self.contacts_service is None:
            self.contacts_service = ContactsService(self.user_id)

        for tentativa in range(5):
            try:
                self.contacts_service.client.Delete(self.contact_feeds[which_feed].entry[contact_on_feed])
            except gdata.client.RequestError, e:
#                    e.status == 402 and
                if '<code>userRateLimitExceeded</code>' in e.body:
                    print 'FALHA NA REMOCAO : causa: %s' % str(e.body)
                    print '(retentativa %d/5)' % (tentativa + 1)
                    sys.stdout.flush()
                    time.sleep(1)
                else:
                    print 'FALHA NA REMOCAO : %s' % str(e.body)
                    print '(desistindo)'
                    raise e
            sys.stdout.flush()
            print '(removido)'
            break

    def get_contacts(self, verbose, emails_only=True):

        def get_feed(client, verbose, feed_number, uri=None):
            if verbose:
                spits_log('#')
            for retryCount in range(5):
                try:
                    if uri == None:
                        feed = client.GetContacts()
                    else:
                        feed = client.GetContacts(uri=uri)
                    return feed
                except gdata.client.RequestError, e:
                    spits_log('error %d getting feed %d of contact list for user %s. cause: %s\n' % (e.status, feed_number, self.user_id, str(e.body)), False)
                    if e.status == 403 and '<code>userRateLimitExceeded</code>' in e.body:
                        spits_log('retrying (%d/5)... ' % (retryCount + 1))
                        time.sleep(retryCount)
                    else:
                        spits_log('unknown reason: giving up...\n')
                        raise e

            spits_log('(retry limit exceeded, giving up)\n')
            raise RuntimeError()

        if self.contact_feeds is None:

            if verbose:
                spits_log('getting contacts for user %s... ' % self.user_id)

            self.contact_feeds = []

            if self.contacts_service is None:
                self.contacts_service = ContactsService(self.user_id)

            feed_number = 1
            feed = get_feed(self.contacts_service.client, verbose, feed_number)
            self.contact_feeds.append(feed)

            while feed:
                nextFeed = feed.GetNextLink()
                feed = None
                if nextFeed:
                    feed_number = feed_number + 1
                    feed = get_feed(self.contacts_service.client, verbose, feed_number, nextFeed.href)
                    self.contact_feeds.append(feed)

        return_value = []

        for feed in self.contact_feeds:
            for entry in feed.entry:

                emails = []
                for email in entry.email:
                    emails.append(email.address.strip().lower())

                if emails_only:
                    return_value.append({'mail': emails})
                else:
                    # TODO: implement it!
                    raise NotImplementedError()

        if verbose:
            spits_log('(success)\n')

        return return_value


def spits_log(message, flush=True):
    sys.stdout.write(message)
    if flush:
        sys.stdout.flush()


class Service(object):

    json_data = None

    def __init__(self, scope, conect_as=None):

        self.credentials = None
        if conect_as is None:
            self.credentials = oauth2client.client.SignedJwtAssertionCredentials(Service.json_data[u'client_email'],
                                                                            Service.json_data[u'private_key'],
                                                                            scope=[scope, ])
        else:
            self.credentials = oauth2client.client.SignedJwtAssertionCredentials(Service.json_data[u'client_email'],
                                                                            Service.json_data[u'private_key'],
                                                                            scope=[scope, ],
                                                                            sub=conect_as)

        http_tmp = httplib2.Http()
        self.http = self.credentials.authorize(http_tmp)


class ContactsService(Service):
    def __init__(self, usuario):
        super(ContactsService, self).__init__(scope='https://www.google.com/m8/feeds', conect_as=usuario)

        gd_client = gdata.contacts.client.ContactsClient()

        oauth2_token = gdata.gauth.OAuth2TokenFromCredentials(self.credentials)

        self.client = oauth2_token.authorize(gd_client)


class Command(object):

    @staticmethod
    def test_domain(email, options):
        return not options.domain or email.endswith(options.domain)

    # TODO: improve it (as is, searches only substrings (i.e., "silva@trr4" matches with "joaosilva@trt4.jus.br"
    @staticmethod
    def test_valid(email, options):
        return not options.listofvalidemails or email in open(options.listofvalidemails).read()

    @staticmethod
    def do_list(googleUser, options):
        for contact_emails in googleUser.get_contacts(options.verbose, emails_only=True):
            for email in contact_emails['mail']:
                if Command.test_domain(email, options):
                    if Command.test_valid(email, options):
                        print email
                    else:
                        print '%s (invalid)' % email

    # TODO: revise
    '''
    def do_kill_contact_all(usuario):
        contatos = usuario.get_contacts(apenas_email=True)
        for i in range(len(contatos)):
            if EXECUCAO_FAKE:
                print 'mataria o contato %d (mail %s)' % (i, contatos[i]['mail'])
            else:
                usuario.contact_delete(i)

    # TODO: revise
    def do_kill_contact_trt4_all(usuario):
        contatos = usuario.get_contacts(apenas_email=True)
        for i in range(len(contatos)):
            achou = False
            for email in contatos[i]['mail']:
                if is_trt4(email):
                    achou = True
                    break

            if achou:
                if EXECUCAO_FAKE:
                    print 'mataria o contato %d (mail %s)' % (i, email)
                else:
                    usuario.contact_delete(i)

    # TODO: revise
    def do_kill_contact_trt4_invalid(usuario):
        raise NotImplementedError
        contatos = usuario.get_contacts(apenas_email=True)
        for i in range(len(contatos)):
            achou = False
            for email in contatos[i]['mail']:
                if is_trt4(email):
                    if not is_valid(email):
                        achou = True
                        break

            if achou:
                print 'mataria o contato %d (mail %s)' % (i, email)
            else:
                usuario.contact_delete(i)

    # TODO: revise
    def do_kill_mail_trt4_invalid(usuario):
        raise NotImplementedError
        contatos = usuario.get_contacts(apenas_email=True)
        for i in range(len(contatos)):
            achou = False
            for email in contatos[i]['mail']:
                if is_trt4(email):
                    if not is_valid(email):
                        achou = True
                        break

            if achou:
                print 'mataria o contato %d (mail %s)' % (i, email)

    '''


def parse_args():

    usage = None
    last_command = None
    for command in dir(Command):
        if command.startswith('do_'):
            if usage:
                if last_command:
                    usage = '%s, "%s"' % (usage, last_command)
                last_command = command[3:]
            else:
                usage = 'usage: %%prog [options] <command> [<user1> [<user2> [...]]], where valid commands are "%s"' % command[3:]
    if last_command:
        usage = '%s or "%s"' % (usage, last_command)

    parser = optparse.OptionParser(usage)
    parser.add_option('-v', '--verbose', action='store_true', default=False,
                      help='enable verbose mode')
    parser.add_option('-d', '--domain', action='store',
                      help='domain to use, if not informed use all domains')
    parser.add_option('-l', '--listofvalidemails', action='store',
                      help='text file whith a list o valid emails')
    parser.add_option('-n', '--nochange', action='store_true', default=False,
                      help='credentials file')
    parser.add_option('-c', '--credentials', action='store', default='/etc/gam_contacts_credentials.json',
                      help='credentials file')
    (options, args) = parser.parse_args()

    if len(args) < 1:
        parser.error('command must be informed')

    if not 'do_' + args[0] in dir(Command):
        parser.error('invalid command')

    command = args[0].lower()

    if len(args) < 2:
        parser.error('at least one user must be informed')
    users = args[1:]

    if options.domain:
        if options.domain[0] == '@':
            options.domain = options.domain.lower()
        else:
            options.domain = '@%s' % options.domain.lower()

    if options.listofvalidemails:
        if not os.path.isfile(options.listofvalidemails):
            parser.error('file "%s" not found' % options.listofvalidemails)

    if not os.path.isfile(options.credentials):
        parser.error('credentials file "%s" not found' % options.credentials)

    try:
        json_string = open(options.credentials).read()
        Service.json_data = json.loads(json_string)
    except IOError, e:
        parser.error('error reading credentails file "%s": %s' % (options.credentials, str(e)))

    # TODO: revise daqui em diante
    '''
    if len(sys.argv) < 2 or not sys.argv[1] in comando:
        print 'syntax: limpa_contatos.py <COMANDO> <USUARIO1> [<USUARIO2> [...]], onde <COMANDO> pode ser:\n'\
              '        list : lista os contatos (apenas mails)\n'\
              '        kill_contact_all : apaga todos contatos'\
              '        kill_contact_trt4_all : apaga todos contatos que contenham emails trt4.jus.br'\
              '        kill_contact_trt4_invalid : apaga os contatos que contenham emails trt4.jus.br que sao invalidos'\
              '        kill_mail_trt4_all : apaga todos emails trt4.jus.br'\
              '        kill_mail_trt4_invalid : apaga os emails trt4.jus.br que sao invalidos'
        sys.exit(1)
    '''

    return (options, command, users)


def main():

    (options, command, users) = parse_args()

    callableCommand = getattr(Command(), 'do_%s' % command)
    for user in users:
        googleUser = GoogleUser(user)
        callableCommand(googleUser, options)

if __name__ == '__main__':
    main()
