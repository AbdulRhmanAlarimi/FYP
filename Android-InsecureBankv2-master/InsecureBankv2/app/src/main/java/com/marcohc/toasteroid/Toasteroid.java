package com.marcohc.toasteroid;

import android.content.Context;
import android.widget.Toast;

public class Toasteroid {

    public static class STYLES {
        public static final int WARNING = 0;
        public static final int ERROR = 1;
        public static final int SUCCESS = 2;
    }

    public static final int LENGTH_SHORT = Toast.LENGTH_SHORT;
    public static final int LENGTH_LONG = Toast.LENGTH_LONG;

    public static void show(Context context, String message, int style, int length) {
        Toast.makeText(context, message, length).show();
    }
}
