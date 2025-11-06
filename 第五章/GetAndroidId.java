import java.lang.reflect.Method;

import javax.naming.Context;

public class GetAndroidId {

    public String getAndroidIdByBinder(Context context) {
        try {
            // Acquire the ContentProvider
            Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
            Method currentActivityThreadMethod = activityThreadClass.getMethod("currentActivityThread");
            Object currentActivityThread = currentActivityThreadMethod.invoke(null);
            Method acquireProviderMethod = activityThreadClass.getMethod("acquireProvider", Context.class, String.class,
                    int.class, boolean.class);
            Object provider = acquireProviderMethod.invoke(currentActivityThread, context, "settings", 0, true);

            // Get the Binder
            Class<?> iContentProviderClass = Class.forName("android.content.IContentProvider");
            Field mRemoteField = provider.getClass().getDeclaredField("mRemote");
            mRemoteField.setAccessible(true);
            IBinder binder = (IBinder) mRemoteField.get(provider);

            // Create the Parcel for the arguments
            Parcel data = Parcel.obtain();
            data.writeInterfaceToken("android.content.IContentProvider");
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                context.getAttributionSource().writeToParcel(data, 0);
                data.writeString("settings"); // authority
                data.writeString("GET_secure"); // method
                data.writeString("android_id"); // stringArg
                data.writeBundle(Bundle.EMPTY);
            } else if (android.os.Build.VERSION.SDK_INT == android.os.Build.VERSION_CODES.R) {
                // android 11
                data.writeString(context.getPackageName());
                data.writeString(null); // featureId

                data.writeString("settings"); // authority
                data.writeString("GET_secure"); // method
                data.writeString("android_id"); // stringArg
                data.writeBundle(Bundle.EMPTY);
            } else if (android.os.Build.VERSION.SDK_INT == android.os.Build.VERSION_CODES.Q) {
                // android 10
                data.writeString(context.getPackageName());

                data.writeString("settings"); // authority
                data.writeString("GET_secure"); // method
                data.writeString("android_id"); // stringArg
                data.writeBundle(Bundle.EMPTY);
            } else {
                data.writeString(context.getPackageName());

                data.writeString("GET_secure"); // method
                data.writeString("android_id"); // stringArg
                data.writeBundle(Bundle.EMPTY);
            }

            Parcel reply = Parcel.obtain();
            binder.transact((int) iContentProviderClass.getDeclaredField("CALL_TRANSACTION").get(null), data, reply, 0);
            reply.readException();
            Bundle bundle = reply.readBundle();
            reply.recycle();
            data.recycle();

            return bundle.getString("value");
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}