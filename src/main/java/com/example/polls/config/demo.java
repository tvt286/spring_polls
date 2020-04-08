package com.example.polls.config;

import javafx.application.Application;
import javafx.stage.Stage;

import java.util.regex.Pattern;

public class demo extends Application {

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        Pattern pattern =  Pattern.compile("dsds");
        if (pattern.matcher("D").matches()){

        }

    }
}
