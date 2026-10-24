package com.android.insecurebankv2;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/*
The class that manages the WebView functionality used in the application
@author Dinesh Shetty
*/
public class MyWebViewClient extends WebViewClient {
	@Override
	public boolean shouldOverrideUrlLoading(WebView view, String url) {

		//hook me-03
		Rasp.webview(url, "LINK", view.getSettings().getJavaScriptEnabled(), "MyWebViewClient");

		
		view.loadUrl(url);
		return true;
	}
}