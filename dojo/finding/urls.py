from django.conf.urls import url

from dojo.finding import views

urlpatterns = [
    #  findings
    url(r'^finding$', views.open_findings,
        name='findings'),
    url(r'^finding/open$', views.open_findings,
        name='open_findings'),
    url(r'^finding/closed$', views.closed_findings,
        name='closed_findings'),
    url(r'^finding/accepted', views.accepted_findings,
        name='accepted_findings'),
    url(r'^finding/(?P<fid>\d+)$', views.view_finding,
        name='view_finding'),
    url(r'^finding/(?P<fid>\d+)/edit$',
        views.edit_finding, name='edit_finding'),
    url(r'^finding/(?P<fid>\d+)/touch',
        views.touch_finding, name='touch_finding'),
    url(r'^finding/(?P<fid>\d+)/delete$',
        views.delete_finding, name='delete_finding'),
    url(r'^finding/(?P<fid>\d+)/mktemplate$', views.mktemplate,
        name='mktemplate'),
    url(r'^finding/(?P<fid>\d+)/close$', views.close_finding,
        name='close_finding'),
    url(r'^finding/(?P<fid>\d+)/open', views.reopen_finding,
        name='reopen_finding'),
    url(r'^finding/(?P<tid>\d+)/note/(?P<nid>\d+)/delete$',
        views.delete_finding_note, name='delete_finding_note'),
    url(r'^finding/(?P<fid>\d+)/manage_images', views.manage_images,
        name='manage_images'),
    # stub findings

    url(r'^stub_finding/(?P<fid>\d+)/promote',
        views.promote_to_finding, name='promote_to_finding'),
    url(r'^stub_finding/(?P<fid>\d+)/delete$',
        views.delete_stub_finding, name='delete_stub_finding'),

    # template findings

    url(r'^template$', views.templates,
        name='templates'),
    url(r'^template/add$', views.add_template,
        name='add_template'),
    url(r'^template/(?P<tid>\d+)/edit$',
        views.edit_template, name='edit_template'),
    url(r'^template/(?P<tid>\d+)/delete',
        views.delete_template, name='delete_template'),
]
