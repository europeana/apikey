package univ;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.stereotype.Component;
import univ.repos.ApiKeyRepo;

@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplicationBuilder builder = new SpringApplicationBuilder();
        builder.sources(Application.class).run(args);
    }

    @Component
    public static class SampleDataPopulator implements CommandLineRunner {

        @Autowired
        private ApiKeyRepo apiKeyRepo;

        @Override
        public void run(String... args) throws Exception {
        }

//        private ApiKey saveIfNew(ApiKey apikey) {
//            Optional<ApiKey> fromDb = this.courseRepo.findByCourseCode(apikey.getCourseCode());
//
//            if (!fromDb.isPresent()) {
//                return this.courseRepo.save(apikey);
//            }
//            return fromDb.get();
//        }
//        private Teacher sampleTeacher(String name, String department) {
//            return new Teacher(name, department);
//        }

//        private ApiKey sampleCourse(String courseCode, String courseName) {
//            return new ApiKey(courseCode, courseName);
//        }
    }


}
