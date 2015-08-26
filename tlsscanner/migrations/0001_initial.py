# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import tlsscanner.models
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Certificate',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, primary_key=True, auto_created=True)),
                ('pem', models.TextField()),
                ('version', models.PositiveSmallIntegerField()),
                ('serial', models.TextField()),
                ('sigAlgo', models.TextField()),
                ('issuer', models.TextField()),
                ('notBefore', models.DateTimeField()),
                ('notAfter', models.DateTimeField()),
                ('life_at_report', models.TextField()),
                ('subject', models.TextField()),
                ('ext_bc', models.TextField()),
                ('ext_ku', models.TextField()),
                ('ext_eku', models.TextField()),
                ('ext_aia', models.TextField()),
                ('ext_crl', models.TextField()),
                ('ext_cp', models.TextField()),
                ('ext_san', models.TextField()),
                ('ext_aki', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='PublicKey',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, primary_key=True, auto_created=True)),
                ('pubkey_type', models.TextField()),
                ('pubkey_size', models.PositiveSmallIntegerField()),
                ('pubkey_data', models.TextField()),
                ('pubkey_data_name', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='ScanResult',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, primary_key=True, auto_created=True)),
                ('openssl_ciphers', models.TextField()),
                ('openssl_version', models.TextField()),
                ('date', models.DateTimeField()),
                ('requestor_ip', models.GenericIPAddressField()),
            ],
        ),
        migrations.CreateModel(
            name='ServerDetails',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, primary_key=True, auto_created=True)),
                ('server_geo', models.TextField()),
                ('server_whois', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='Session',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, primary_key=True, auto_created=True)),
                ('date', models.DateTimeField()),
                ('hostname', models.TextField()),
                ('server_ip', models.GenericIPAddressField()),
                ('server_port', models.IntegerField()),
                ('server_random', models.TextField()),
                ('server_random_date', models.DateField()),
                ('client_random', models.TextField()),
                ('client_random_date', models.DateField()),
                ('master_key', models.TextField()),
                ('session_id', models.TextField()),
                ('session_ticket', models.TextField()),
                ('session_ticket_lifetime', models.TextField()),
                ('server_cipher', models.TextField()),
                ('tls_version', models.TextField()),
                ('tls_kx', models.TextField()),
                ('tls_auth', models.TextField()),
                ('tls_enc', models.TextField()),
                ('tls_cmode', models.TextField()),
                ('tls_mac', models.TextField()),
                ('server_http_response', models.TextField()),
                ('certificate', models.OneToOneField(to='tlsscanner.Certificate', default=tlsscanner.models.certificate_default)),
                ('server_details', models.OneToOneField(to='tlsscanner.ServerDetails', default=tlsscanner.models.serverdetails_default)),
            ],
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, primary_key=True, auto_created=True)),
                ('website', models.URLField(blank=True)),
                ('picture', models.ImageField(upload_to='profile_images', blank=True)),
                ('user', models.OneToOneField(to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='scanresult',
            name='session',
            field=models.OneToOneField(to='tlsscanner.Session', default=tlsscanner.models.session_default),
        ),
        migrations.AddField(
            model_name='certificate',
            name='pubkey',
            field=models.OneToOneField(to='tlsscanner.PublicKey', default=tlsscanner.models.pubkey_default),
        ),
    ]
