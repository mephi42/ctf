package com.inso.ins24.utils;

import android.os.Parcel;
import android.os.Parcelable;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class JSONBuilder implements Parcelable {
    private static final Gson JSON = new GsonBuilder().create();
    public Object data;

    public JSONBuilder() {
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(this.data.getClass().getCanonicalName());
        parcel.writeString(JSONBuilder.JSON.toJson(this.data));
    }
}


