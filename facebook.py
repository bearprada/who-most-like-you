#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os.path
import tornado.auth
import tornado.escape
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import json
import urlparse

from tornado.options import define, options

define("port", default=os.environ['PORT'], help="run on the given port", type=int)
define("facebook_api_key", help="your Facebook application API key",
       default="128422253907704")
define("facebook_secret", help="your Facebook application secret",
       default="9599e644b353d5c5607f3201a15614ae")


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/locki", ReporterHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
        ]
        settings = dict(
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/auth/login",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
            facebook_api_key=options.facebook_api_key,
            facebook_secret=options.facebook_secret,
            ui_modules={"Post": PostModule},
            debug=True,
            autoescape=None,
        )
        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_json = self.get_secure_cookie("user")
        if not user_json: return None
        return tornado.escape.json_decode(user_json)

class ReporterHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def get(self):
        print "[debug] user = " + str(self.current_user) 
        self.facebook_request("/me/posts", self._on_like,
                              access_token=self.current_user["access_token"])
        self.o = {'name':'likes' , 'children':[]}

    def _get_url_param(self,url,key):
        parsed = urlparse.urlparse(url)
        return urlparse.parse_qs(parsed.query)[key]

    @tornado.web.asynchronous
    def _on_like(self,likes):
        #print " ------------ get likes : " + str(likes)
        self.set_header('Content-Type', 'application/json')
        if likes is None:
            #if(self.o['children'])
            #e = {'error':'you are not login at facebook'}
            self.write(tornado.escape.json_encode(self.o))
            self.finish()
        else:
            r = {}
            for p in likes["data"]:
                for l in p["likes"]["data"]:
                    fid = l["name"]
                    if fid in r:
                    #if fid in userName:
                        r[fid] = r[fid] +1
                    else:
                        r[fid] = 1
            #print "result : " + str(r)
            for k in r:
                self.o["children"].append({'name':k , 'size':r[k]})
            #print "json : " + str(o)
            next = likes["paging"].get('next',None)
            print "[PAGING] next = " + next 
            if  next != None:
                self.facebook_request("/"+str(self.current_user['id'])+"/posts", 
                              self._on_like,
                              post_args={'until':self._get_url_param(next,'until')[0]},
                              access_token=self.current_user["access_token"])
            else:
                self.write(tornado.escape.json_encode(self.o))
                self.finish()
        

class MainHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def get(self):
        #print "[debug] user = " + str(self.current_user) 
        #self.facebook_request("/me/home", self._on_stream,
        self.facebook_request("/me/posts", self.async_callback(self._on_like),
                              access_token=self.current_user["access_token"])
        #self._on_like()

    def _on_like(self,likes):
        #print "get likes : " + str(likes)
        if likes is None:
            self.redirect("/auth/login")
            return
        self.render("likes.html") 

    def _on_stream(self, stream):
        if stream is None:
            # Session may have expired
            self.redirect("/auth/login")
            return
        self.render("stream.html", stream=stream)


class AuthLoginHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.asynchronous
    def get(self):
        my_url = (self.request.protocol + "://" + self.request.host +
                  "/auth/login?next=" +
                  tornado.escape.url_escape(self.get_argument("next", "/")))
        if self.get_argument("code", False):
            self.get_authenticated_user(
                redirect_uri=my_url,
                client_id=self.settings["facebook_api_key"],
                client_secret=self.settings["facebook_secret"],
                code=self.get_argument("code"),
                callback=self._on_auth)
            return
        self.authorize_redirect(redirect_uri=my_url,
                                client_id=self.settings["facebook_api_key"],
                                extra_params={"scope": "read_stream"})
    
    def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, "Facebook auth failed")
        self.set_secure_cookie("user", tornado.escape.json_encode(user))
        self.redirect(self.get_argument("next", "/"))


class AuthLogoutHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    def get(self):
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", "/"))


class PostModule(tornado.web.UIModule):
    def render(self, post):
        return self.render_string("modules/post.html", post=post)


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
