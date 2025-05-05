/**
 * 优化后的 Cloudflare Worker 反向代理脚本
 */

// 替换成你想镜像的站点
const upstream = 'cdn.jsdelivr.net'

// 如果那个站点有专门的移动适配站点，否则保持和上面一致
const upstream_mobile = 'cdn.jsdelivr.net'

const blocked_region = ['KP']
const blocked_ip_address = ['0.0.0.0', '127.0.0.1']

const replace_dict = {
    '$upstream': '$custom_domain',
    '//cdn.jsdelivr.net': ''
}

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
})

async function handleRequest(request) {
    const region = (request.headers.get('cf-ipcountry') || '').toUpperCase();
    const ip_address = request.headers.get('cf-connecting-ip');
    const user_agent = request.headers.get('user-agent') || '';
    const url = new URL(request.url);
    const url_host = url.host;

    if (url.protocol === 'http:') {
        url.protocol = 'https:';
        return Response.redirect(url.href, 301);
    }

    if (blocked_region.includes(region)) {
        return new Response('Access denied: WorkersProxy is not available in your region yet.', { status: 403 });
    }

    if (blocked_ip_address.includes(ip_address)) {
        return new Response('Access denied: Your IP address is blocked by WorkersProxy.', { status: 403 });
    }

    const isDesktop = await isDesktopDevice(user_agent);
    const upstream_domain = isDesktop ? upstream : upstream_mobile;
    url.host = upstream_domain;

    const new_request_headers = new Headers(request.headers);
    new_request_headers.set('Host', upstream_domain);
    new_request_headers.set('Referer', url.href);

    const original_response = await fetch(url.href, {
        method: request.method,
        headers: new_request_headers,
        body: request.body,
        redirect: 'follow'
    });

    const original_response_clone = original_response.clone();
    const content_type = original_response.headers.get('content-type') || '';
    const response_headers = new Headers(original_response.headers);

    response_headers.set('access-control-allow-origin', '*');
    response_headers.set('access-control-allow-credentials', 'true');
    response_headers.delete('content-security-policy');
    response_headers.delete('content-security-policy-report-only');
    response_headers.delete('clear-site-data');

    let response_body;
    if (content_type.toLowerCase().includes('text/html')) {
        response_body = await replaceResponseText(original_response_clone, upstream_domain, url_host);
    } else {
        response_body = original_response_clone.body;
    }

    return new Response(response_body, {
        status: original_response.status,
        headers: response_headers
    });
}

async function replaceResponseText(response, upstream_domain, host_name) {
    let text = await response.text();

    for (let [key, value] of Object.entries(replace_dict)) {
        if (key === '$upstream') key = upstream_domain;
        if (key === '$custom_domain') key = host_name;
        if (value === '$upstream') value = upstream_domain;
        if (value === '$custom_domain') value = host_name;

        const re = new RegExp(escapeRegExp(key), 'g');
        text = text.replace(re, value);
    }

    return text;
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function isDesktopDevice(user_agent) {
    const mobileAgents = ["Android", "iPhone", "SymbianOS", "Windows Phone", "iPad", "iPod"];
    return !mobileAgents.some(agent => user_agent.includes(agent));
}
