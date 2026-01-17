package com.security.vulnscanner.repository;

import com.security.vulnscanner.model.Target;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TargetRepository extends JpaRepository<Target, Long> {
    List<Target> findByUserId(Long userId);
    List<Target> findByUserIdAndType(Long userId, Target.TargetType type);
}
