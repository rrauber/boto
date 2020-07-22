# Copyright (c) 2013 Amazon.com, Inc. or its affiliates.  All Rights Reserved
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish, dis-
# tribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to the fol-
# lowing conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABIL-
# ITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
# SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
from tests.compat import unittest
from tests.unit import AWSMockServiceTestCase
from tests.unit import MockServiceWithConfigTestCase

from boto.s3.connection import S3Connection, HostRequiredError
from boto.s3.connection import S3ResponseError, Bucket


class TestSignatureAlteration(AWSMockServiceTestCase):
    connection_class = S3Connection

    def test_unchanged(self):
        self.assertEqual(
            self.service_connection._required_auth_capability(),
            ['hmac-v4-s3']
        )

    def test_switched(self):
        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more',
            host='s3.cn-north-1.amazonaws.com.cn'
        )
        self.assertEqual(
            conn._required_auth_capability(),
            ['hmac-v4-s3']
        )


class TestAnon(MockServiceWithConfigTestCase):
    connection_class = S3Connection

    def test_generate_url(self):
        conn = self.connection_class(
            anon=True,
            host='s3.amazonaws.com'
        )
        url = conn.generate_url(0, 'GET', bucket='examplebucket', key='test.txt')
        self.assertNotIn('Signature=', url)

    def test_anon_default_taken_from_config_opt(self):
        self.config = {
            's3': {
                # Value must be a string for `config.getbool` to not crash.
                'no_sign_request': 'True',
            }
        }

        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more',
            host='s3.amazonaws.com',
        )
        url = conn.generate_url(
            0, 'GET', bucket='examplebucket', key='test.txt')
        self.assertNotIn('Signature=', url)

    def test_explicit_anon_arg_overrides_config_value(self):
        self.config = {
            's3': {
                # Value must be a string for `config.getbool` to not crash.
                'no_sign_request': 'True',
            }
        }

        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more',
            host='s3.amazonaws.com',
            anon=False
        )
        url = conn.generate_url(
            0, 'GET', bucket='examplebucket', key='test.txt')
        self.assertIn('Signature=', url)


class TestPresigned(MockServiceWithConfigTestCase):
    connection_class = S3Connection

    def test_presign_respect_query_auth(self):
        self.config = {
            's3': {
                'use-sigv4': False,
            }
        }

        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more',
            host='s3.amazonaws.com'
        )

        url_enabled = conn.generate_url(86400, 'GET', bucket='examplebucket',
                                        key='test.txt', query_auth=True)

        url_disabled = conn.generate_url(86400, 'GET', bucket='examplebucket',
                                         key='test.txt', query_auth=False)
        self.assertIn('Signature=', url_enabled)
        self.assertNotIn('Signature=', url_disabled)


class TestSigV4HostError(MockServiceWithConfigTestCase):
    connection_class = S3Connection

    def test_historical_behavior(self):
        self.assertEqual(
            self.service_connection._required_auth_capability(),
            ['hmac-v4-s3']
        )
        self.assertEqual(self.service_connection.host, 's3.amazonaws.com')

    def test_sigv4_opt_in(self):
        host_value = 's3.cn-north-1.amazonaws.com.cn'

        # Switch it at the config, so we can check to see how the host is
        # handled.
        self.config = {
            's3': {
                'use-sigv4': True,
            }
        }

        # Ensure passing a ``host`` in the connection args still works.
        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more',
            host=host_value
        )
        self.assertEqual(
            conn._required_auth_capability(),
            ['hmac-v4-s3']
        )
        self.assertEqual(
            conn.host,
            host_value
        )

        # Ensure that the host is populated from our config if one is not
        # provided when creating a connection.
        self.config = {
            's3': {
                'host': host_value,
                'use-sigv4': True,
            }
        }
        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more'
        )
        self.assertEqual(
            conn._required_auth_capability(),
            ['hmac-v4-s3']
        )
        self.assertEqual(
            conn.host,
            host_value
        )


class TestSigV4Presigned(MockServiceWithConfigTestCase):
    connection_class = S3Connection

    def test_sigv4_presign(self):
        self.config = {
            's3': {
                'use-sigv4': True,
            }
        }

        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more',
            host='s3.amazonaws.com'
        )

        # Here we force an input iso_date to ensure we always get the
        # same signature.
        url = conn.generate_url_sigv4(86400, 'GET', bucket='examplebucket',
                                      key='test.txt',
                                      iso_date='20140625T000000Z')

        self.assertIn(
            'a937f5fbc125d98ac8f04c49e0204ea1526a7b8ca058000a54c192457be05b7d',
            url)

    def test_sigv4_presign_respects_is_secure(self):
        self.config = {
            's3': {
                'use-sigv4': True,
            }
        }

        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more',
            host='s3.amazonaws.com',
            is_secure=True,
        )

        url = conn.generate_url_sigv4(86400, 'GET', bucket='examplebucket',
                                      key='test.txt')
        self.assertTrue(url.startswith(
            'https://examplebucket.s3.amazonaws.com/test.txt?'))

        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more',
            host='s3.amazonaws.com',
            is_secure=False,
        )

        url = conn.generate_url_sigv4(86400, 'GET', bucket='examplebucket',
                                      key='test.txt')
        self.assertTrue(url.startswith(
            'http://examplebucket.s3.amazonaws.com/test.txt?'))

    def test_sigv4_presign_optional_params(self):
        self.config = {
            's3': {
                'use-sigv4': True,
            }
        }

        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more',
            security_token='token',
            host='s3.amazonaws.com'
        )

        url = conn.generate_url_sigv4(86400, 'GET', bucket='examplebucket',
                                      key='test.txt', version_id=2)

        self.assertIn('VersionId=2', url)
        self.assertIn('X-Amz-Security-Token=token', url)

    def test_sigv4_presign_respect_query_auth(self):
        self.config = {
            's3': {
                'use-sigv4': True,
            }
        }

        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more',
            host='s3.amazonaws.com'
        )

        url_enabled = conn.generate_url(86400, 'GET', bucket='examplebucket',
                                        key='test.txt', query_auth=True)

        url_disabled = conn.generate_url(86400, 'GET', bucket='examplebucket',
                                         key='test.txt', query_auth=False)
        self.assertIn('Signature=', url_enabled)
        self.assertNotIn('Signature=', url_disabled)

    def test_sigv4_presign_headers(self):
        self.config = {
            's3': {
                'use-sigv4': True,
            }
        }

        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more',
            host='s3.amazonaws.com'
        )

        headers = {'x-amz-meta-key': 'val'}
        url = conn.generate_url_sigv4(86400, 'GET', bucket='examplebucket',
                                      key='test.txt', headers=headers)

        self.assertIn('host', url)
        self.assertIn('x-amz-meta-key', url)

    def test_sigv4_presign_response_headers(self):
        self.config = {
            's3': {
                'use-sigv4': True,
            }
        }

        conn = self.connection_class(
            aws_access_key_id='less',
            aws_secret_access_key='more',
            host='s3.amazonaws.com'
        )

        response_headers = {'response-content-disposition': 'attachment; filename="file.ext"'}
        url = conn.generate_url_sigv4(86400, 'GET', bucket='examplebucket',
                                      key='test.txt', response_headers=response_headers)

        self.assertIn('host', url)
        self.assertIn('response-content-disposition', url)


class TestUnicodeCallingFormat(AWSMockServiceTestCase):
    connection_class = S3Connection

    def default_body(self):
        return """<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
  <Owner>
    <ID>bcaf1ffd86f461ca5fb16fd081034f</ID>
    <DisplayName>webfile</DisplayName>
  </Owner>
  <Buckets>
    <Bucket>
      <Name>quotes</Name>
      <CreationDate>2006-02-03T16:45:09.000Z</CreationDate>
    </Bucket>
    <Bucket>
      <Name>samples</Name>
      <CreationDate>2006-02-03T16:41:58.000Z</CreationDate>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>"""

    def create_service_connection(self, **kwargs):
        kwargs['calling_format'] = u'boto.s3.connection.OrdinaryCallingFormat'
        return super(TestUnicodeCallingFormat,
                     self).create_service_connection(**kwargs)

    def test_unicode_calling_format(self):
        self.set_http_response(status_code=200)
        self.service_connection.get_all_buckets()


class TestHeadBucket(AWSMockServiceTestCase):
    connection_class = S3Connection

    def default_body(self):
        # HEAD requests always have an empty body.
        return ""

    def test_head_bucket_success(self):
        self.set_http_response(status_code=200)
        buck = self.service_connection.head_bucket('my-test-bucket')
        self.assertTrue(isinstance(buck, Bucket))
        self.assertEqual(buck.name, 'my-test-bucket')

    def test_head_bucket_forbidden(self):
        self.set_http_response(status_code=403)

        with self.assertRaises(S3ResponseError) as cm:
            self.service_connection.head_bucket('cant-touch-this')

        err = cm.exception
        self.assertEqual(err.status, 403)
        self.assertEqual(err.error_code, 'AccessDenied')
        self.assertEqual(err.message, 'Access Denied')

    def test_head_bucket_notfound(self):
        self.set_http_response(status_code=404)

        with self.assertRaises(S3ResponseError) as cm:
            self.service_connection.head_bucket('totally-doesnt-exist')

        err = cm.exception
        self.assertEqual(err.status, 404)
        self.assertEqual(err.error_code, 'NoSuchBucket')
        self.assertEqual(err.message, 'The specified bucket does not exist')

    def test_head_bucket_other(self):
        self.set_http_response(status_code=405)

        with self.assertRaises(S3ResponseError) as cm:
            self.service_connection.head_bucket('you-broke-it')

        err = cm.exception
        self.assertEqual(err.status, 405)
        # We don't have special-cases for this error status.
        self.assertEqual(err.error_code, None)
        self.assertEqual(err.message, '')


class TestGetS3Host(AWSMockServiceTestCase):
    connection_class = S3Connection

    def test_get_s3_host_no_region(self):
        endpoint = 'a.s3.amazonaws.com'
        host = self.service_connection._get_s3_host(endpoint)
        self.assertEqual(host, 's3.amazonaws.com')

    def test_get_s3_host_with_region(self):
        endpoint = 'a.s3.us-east-2.amazonaws.com'
        host = self.service_connection._get_s3_host(endpoint)
        self.assertEqual(host, 's3.us-east-2.amazonaws.com')

    def test_get_s3_host_multiple_s3_occurrences(self):
        endpoint = 'a.s3.a.s3.amazonaws.com'
        host = self.service_connection._get_s3_host(endpoint)
        self.assertEqual(host, 's3.amazonaws.com')

    def test_get_s3_host_s3_in_region(self):
        endpoint = 'a.s3.asdf-s3.amazonaws.com'
        host = self.service_connection._get_s3_host(endpoint)
        self.assertEqual(host, 's3.asdf-s3.amazonaws.com')

    def test_get_s3_host_no_s3(self):
        endpoint = 'a.some-other-storage-service.com'
        host = self.service_connection._get_s3_host(endpoint)
        self.assertIsNone(host)


class TestChangeS3Host(AWSMockServiceTestCase):
    connection_class = S3Connection
    new_host = 'test-host'

    def test_change_s3_host_no_region(self):
        endpoint = 'a.s3.amazonaws.com'
        host = self.service_connection._change_s3_host(endpoint, self.new_host)
        self.assertEqual(host, 'a.test-host')

    def test_change_s3_host_with_region(self):
        endpoint = 'a.s3.us-east-2.amazonaws.com'
        host = self.service_connection._change_s3_host(endpoint, self.new_host)
        self.assertEqual(host, 'a.test-host')

    def test_change_s3_host_multiple_s3_occurrences(self):
        endpoint = 'a.s3.a.s3.amazonaws.com'
        host = self.service_connection._change_s3_host(endpoint, self.new_host)
        self.assertEqual(host, 'a.s3.a.test-host')

    def test_change_s3_host_s3_in_region(self):
        endpoint = 'a.s3.asdf-s3.amazonaws.com'
        host = self.service_connection._change_s3_host(endpoint, self.new_host)
        self.assertEqual(host, 'a.test-host')

    def test_get_s3_host_no_s3(self):
        endpoint = 'a.some-other-storage-service.com'
        host = self.service_connection._change_s3_host(endpoint, self.new_host)
        self.assertIsNone(host)


class TestFixS3EndpointRegion(AWSMockServiceTestCase):
    connection_class = S3Connection

    def test_fix_s3_endpoint_region_no_endpoint(self):
        new_endpoint = self.service_connection._fix_s3_endpoint_region(
            None, 'eu-west-1')
        self.assertIsNone(new_endpoint)

    def test_fix_s3_endpoint_region_no_region(self):
        endpoint = 'a.s3.us-east-2.amazonaws.com'
        new_endpoint = self.service_connection._fix_s3_endpoint_region(
            endpoint, None)
        self.assertIsNone(new_endpoint)

    def test_fix_s3_endpoint_region_region_in_endpoint(self):
        endpoint = 'a.s3.us-east-2.amazonaws.com'
        new_region = 'ap-south-1'
        new_endpoint = self.service_connection._fix_s3_endpoint_region(
            endpoint, new_region)
        self.assertEqual(new_endpoint, 'a.s3.ap-south-1.amazonaws.com')

    def test_fix_s3_endpoint_region_no_region_in_endpoint(self):
        endpoint = 'a.s3.amazonaws.com'
        new_region = 'ap-south-1'
        new_endpoint = self.service_connection._fix_s3_endpoint_region(
            endpoint, new_region)
        self.assertEqual(new_endpoint, 'a.s3.ap-south-1.amazonaws.com')

    def test_fix_s3_endpoint_region_non_s3_endpoint(self):
        endpoint = 'a.some-other-storage-service.com'
        new_region = 'ap-south-1'
        new_endpoint = self.service_connection._fix_s3_endpoint_region(
            endpoint, new_region)
        self.assertIsNone(new_endpoint)


class TestGetCorrectS3EndpointFromResponse(AWSMockServiceTestCase):
    connection_class = S3Connection

    def setUp(self):
        super(TestGetCorrectS3EndpointFromResponse, self).setUp()

        # this function is really long and does not fit on one line below.
        sc = self.service_connection
        self.endpoint_alias = sc._get_correct_s3_endpoint_from_response

    def build_request(self, method='HEAD', path='/', auth_path='/', params=None,
                      headers=None, data=None, host=''):
        """Add defaults for less noise in the tests."""
        return self.service_connection.build_base_http_request(
            method, path, auth_path,
            params, headers, data, host)

    def test_callable_get_header_has_region(self):
        host = 'bucket.s3.amazonaws.com'
        headers = {'x-amz-bucket-region': 'us-east-2'}
        endpoint = self.endpoint_alias(
            self.build_request(host=host),
            S3ResponseError('status', 'reason'),
            headers.get
        )
        self.assertEqual(endpoint, 'bucket.s3.us-east-2.amazonaws.com')

    def test_callable_get_header_no_region_checks_error(self):
        host = 'bucket.s3.amazonaws.com'
        headers = {}
        body = '<Region>us-east-2</Region>'
        err = S3ResponseError(400, 'reason', body=body)
        endpoint = self.endpoint_alias(
            self.build_request(host=host),
            err,
            headers.get
        )
        self.assertEqual(endpoint, 'bucket.s3.us-east-2.amazonaws.com')

    def test_uses_parsed_region(self):
        host = 'bucket.s3.amazonaws.com'
        body = '<Region>us-east-2</Region>'
        err = S3ResponseError(400, 'reason', body=body)
        endpoint = self.endpoint_alias(
            self.build_request(host=host),
            err,
            None
        )
        self.assertEqual(endpoint, 'bucket.s3.us-east-2.amazonaws.com')

    def test_uses_parsed_location_constraint(self):
        host = 'bucket.s3.amazonaws.com'
        body = '<LocationConstraint>us-east-2</LocationConstraint>'
        err = S3ResponseError(400, 'reason', body=body)
        endpoint = self.endpoint_alias(
            self.build_request(host=host),
            err,
            None
        )
        self.assertEqual(endpoint, 'bucket.s3.us-east-2.amazonaws.com')

    def test_illegal_constraint_exception_matches_regex(self):
        host = 'bucket.s3.amazonaws.com'
        body = (
            '<Error><Code>IllegalLocationConstraintException</Code><Message>'
            'The us-east-2 location constraint is incompatible for the region '
            'specific endpoint this request was sent to.</Message><RequestId>'
            'asdf</RequestId><HostId>asdf</HostId></Error>'
        )
        err = S3ResponseError(400, 'reason', body=body)
        endpoint = self.endpoint_alias(
            self.build_request(host=host),
            err,
            None
        )
        self.assertEqual(endpoint, 'bucket.s3.us-east-2.amazonaws.com')

    def test_error_parsed_endpoint(self):
        host = 'bucket.s3.amazonaws.com'
        body = '<Endpoint>use-this-instead</Endpoint>'
        err = S3ResponseError(400, 'reason', body=body)
        endpoint = self.endpoint_alias(
            self.build_request(host=host),
            err,
            None
        )
        self.assertEqual(endpoint, 'use-this-instead')

    def test_illegal_constraint_exception_matches_regex_unspecified(self):
        self.set_http_response(status_code=200)
        host = 'bucket.s3.amazonaws.com'
        body = (
            '<Error><Code>IllegalLocationConstraintException</Code><Message>'
            'The unspecified location constraint is incompatible for the '
            'region specific endpoint this request was sent to.</Message>'
            '<RequestId>asdf</RequestId><HostId>asdf</HostId></Error>'
        )
        err = S3ResponseError(400, 'reason', body=body)
        endpoint = self.endpoint_alias(
            self.build_request(host=host),
            err,
            None
        )

    def test_illegal_constraint_exception_does_not_match_regex(self):
        self.set_http_response(status_code=200)
        host = 'bucket.s3.amazonaws.com'
        body = (
            '<Error><Code>IllegalLocationConstraintException</Code><Message>'
            'some string</Message><RequestId>asdf</RequestId><HostId>asdf'
            '</HostId></Error>'
        )
        err = S3ResponseError(400, 'reason', body=body)
        endpoint = self.endpoint_alias(
            self.build_request(host=host),
            err,
            None
        )

    def test_bucket_head_request_has_region(self):
        self.set_http_response(
            status_code=200,
            header=[('x-amz-bucket-region', 'us-east-2')]
        )

        host = 'bucket.s3.amazonaws.com'
        err = S3ResponseError(400, 'reason')
        endpoint = self.endpoint_alias(
            self.build_request(host=host),
            err,
            None
        )
        self.assertEqual(endpoint, 'bucket.s3.us-east-2.amazonaws.com')

    def test_bucket_head_request_does_not_have_region(self):
        self.set_http_response(status_code=200)

        host = 'bucket.s3.amazonaws.com'
        err = S3ResponseError(400, 'reason')
        endpoint = self.endpoint_alias(
            self.build_request(host=host),
            err,
            None
        )
        self.assertIsNone(endpoint)


class TestChangeS3HostFromError(AWSMockServiceTestCase):
    connection_class = S3Connection

    def setUp(self):
        super(TestChangeS3HostFromError, self).setUp()
        self.request = self.service_connection.build_base_http_request(
            'GET', '/', '/',
            None, None, '', 'bucket.s3.amazonaws.com')

    def test_endpoint_not_none_changes_request(self):
        correct_endpoint = 'bucket.s3.us-east-2.amazonaws.com'
        self.service_connection._get_correct_s3_endpoint_from_response = (
            lambda x, y, z: correct_endpoint
        )

        new_request = self.service_connection._change_s3_host_from_error(
            self.request,
            None
        )

        self.assertEqual(new_request.host, correct_endpoint)

    def test_endpoint_none_returns_none(self):
        self.service_connection._get_correct_s3_endpoint_from_response = (
            lambda x, y, z: None
        )

        new_request = self.service_connection._change_s3_host_from_error(
            self.request,
            None
        )

        self.assertIsNone(new_request)


class TestGetRequestForS3Retry(AWSMockServiceTestCase):
    connection_class = S3Connection

    def test_translate_response_to_error_with_body(self):
        http_request = 'http_request'
        body_bytes = b'<Error></Error>'
        body_decoded = '<Error></Error>'
        response = self.create_response(
            400,
            reason='reason',
            header=[('test', 'header')],
            body=body_bytes
        )

        def validate_function_args(request, error, get_header=None):
            self.assertEqual(request, http_request)
            self.assertEqual(response.status, error.status)
            self.assertEqual(response.reason, error.reason)
            self.assertEqual(body_decoded, error.body)
            self.assertTrue(callable(get_header))

        self.service_connection._change_s3_host_from_error = (
            validate_function_args
        )

        self.service_connection._get_request_for_s3_retry(
            http_request, response, None)

    def test_translate_response_to_error_without_body(self):
        http_request = 'http_request'
        response = self.create_response(400, reason='reason')

        def validate_function_args(request, error, get_header=None):
            self.assertEqual(request, http_request)
            self.assertEqual(response.status, error.status)
            self.assertEqual(response.reason, error.reason)
            self.assertTrue(callable(get_header))

        self.service_connection._change_s3_host_from_error = (
            validate_function_args
        )

        self.service_connection._get_request_for_s3_retry(
            http_request, response, None)

    def test_response_passes_error(self):
        http_request = 'http_request'
        err = S3ResponseError(400, 'reason', '<Error></Error>')

        def validate_function_args(request, error, get_header=None):
            self.assertEqual(request, http_request)
            self.assertEqual(error, err)
            self.assertFalse(callable(get_header))

        self.service_connection._change_s3_host_from_error = (
            validate_function_args
        )

        self.service_connection._get_request_for_s3_retry(
            http_request, None, err)


class TestMakeRequestRegionRetry(AWSMockServiceTestCase):
    connection_class = S3Connection

    def _mock_retry_request(self, request, response, error):
        # for the methods that test the retry logic with a response, not an
        # error, ensure future requests succeed. The functions testing the
        # error logic overwrite this in _mexe_mock.
        self.set_http_response(200)
        return request

    def setUp(self):
        super(TestMakeRequestRegionRetry, self).setUp()

        self.retry_codes = [301, 400]
        self.service_connection._get_request_for_s3_retry = (
            self._mock_retry_request
        )

    def test_aws_response_retry_status_codes(self):
        for code in self.retry_codes:
            self.set_http_response(code)
            response = self.service_connection.make_request(
                'HEAD', bucket='bucket')

            self.assertEqual(response.status, 200)

    def test_aws_response_other_status_no_retry(self):
        self.set_http_response(404)
        response = self.service_connection.make_request(
            'HEAD', bucket='bucket')

        self.assertEqual(response.status, 404)

    def test_retry_request_is_none_returns_original_response(self):
        self.service_connection._get_request_for_s3_retry = (
            lambda *args: None
        )

        for code in self.retry_codes:
            self.set_http_response(code)
            response = self.service_connection.make_request(
                'HEAD', bucket='bucket')

            self.assertEqual(response.status, code)

    def _mexe_mock(self, code):
        def mock_function_using_code(*args, **kwargs):
            # future, retried, calls should have a different status code
            # so that whether or not a retry has occured is detectable.
            self.service_connection._mexe = (
                lambda *args, **kwargs: self.create_response(200)
            )
            raise S3ResponseError(code, 'reason')
        return mock_function_using_code

    def test_aws_exception_retry_status_code(self):
        for code in self.retry_codes:
            self.service_connection._mexe = self._mexe_mock(code)

            response = self.service_connection.make_request(
                'HEAD', bucket='bucket')

            self.assertEqual(response.status, 200)

    def test_aws_exception_other_status_raises_error(self):
        self.service_connection._mexe = self._mexe_mock(404)

        with self.assertRaises(S3ResponseError):
            response = self.service_connection.make_request(
                'HEAD', bucket='bucket')

    def test_retry_request_is_none_raises_original_error(self):
        self.service_connection._get_request_for_s3_retry = (
            lambda *args: None
        )

        for code in self.retry_codes:
            self.service_connection._mexe = self._mexe_mock(code)

            with self.assertRaises(S3ResponseError):
                response = self.service_connection.make_request(
                    'HEAD', bucket='bucket')


if __name__ == "__main__":
    unittest.main()
